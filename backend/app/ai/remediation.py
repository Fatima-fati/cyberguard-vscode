"""Remediation assistee : proposer, confirmer, appliquer, revenir en arriere.

Garanties de ce module :

- **Rien n'est applique sans confirmation explicite** de l'utilisateur.
- **Aucune action a distance** : ni SSH, ni PowerShell, ni commande systeme.
  Le backend ne peut modifier qu'un fichier qu'il atteint lui-meme, sous la
  racine autorisee `AI_REMEDIATION_ROOT`. Sans cette racine, la correction
  reste une proposition et l'ecriture est refusee.
- **Jamais de remplacement de fichier complet** : seule la ligne ciblee est
  modifiee, et uniquement si son contenu actuel correspond encore a ce que
  le modele a analyse.
- **Sauvegarde avant ecriture** et rollback possible.
"""

import asyncio
import difflib
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, ValidationError

from app import i18n, store
from app.ai.openai_client import AIError, AIResponseError, OpenAIClient, get_openai_client
from app.ai.schemas import AINotification, RemediationPreview, RemediationRecord
from app.config import settings

logger = logging.getLogger(__name__)

CONTEXT_LINES = 4


class RemediationError(Exception):
    """Erreur metier de remediation (refus, garde declenchee)."""

    status_code = 409

    def __init__(self, message: str, detail: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.detail = detail


class PatchProposal(BaseModel):
    """Correction ligne a ligne proposee par le modele."""

    original_line: str = ""
    replacement_line: str = ""
    explanation: str = ""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------
# Resolution et controle du fichier cible
# --------------------------------------------------------------------------


def resolve_target(file_name: Optional[str]) -> tuple[Optional[Path], list[str]]:
    """Resout le fichier a corriger. Retourne (chemin, obstacles).

    Chaque obstacle est un message affichable : l'utilisateur doit
    comprendre pourquoi la correction ne peut pas etre appliquee ici.
    """
    blockers: list[str] = []

    if not file_name:
        blockers.append("Aucun fichier n'est identifié dans l'alerte.")
        return None, blockers

    root = settings.remediation_root_path
    if root is None:
        blockers.append(
            "Aucune racine de correction n'est configurée (AI_REMEDIATION_ROOT). "
            "Le backend ne peut pas modifier un fichier situé sur un serveur "
            "distant : appliquez la correction manuellement."
        )
        return None, blockers

    if not root.exists():
        blockers.append(f"La racine configurée est introuvable : {root}")
        return None, blockers

    candidate = Path(file_name)
    target = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()

    # Traversee de repertoire : le chemin doit rester sous la racine.
    try:
        target.relative_to(root)
    except ValueError:
        blockers.append("Le fichier visé est hors de la racine autorisée.")
        return None, blockers

    if not target.exists() or not target.is_file():
        blockers.append(f"Fichier introuvable sous la racine autorisée : {file_name}")
        return None, blockers

    if target.stat().st_size > settings.ai_remediation_max_file_size:
        blockers.append(
            f"Fichier trop volumineux ({target.stat().st_size} octets) pour une "
            "correction automatique."
        )
        return None, blockers

    return target, blockers


def _read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def _excerpt(lines: list[str], line_number: int) -> str:
    start = max(0, line_number - 1 - CONTEXT_LINES)
    end = min(len(lines), line_number + CONTEXT_LINES)
    return "\n".join(
        f"{index + 1:>5} | {lines[index]}" for index in range(start, end)
    )


def build_diff(path: Path, lines: list[str], line_number: int, replacement: str) -> str:
    """Diff unifie de la modification d'une seule ligne."""
    patched = list(lines)
    patched[line_number - 1] = replacement

    return "\n".join(
        difflib.unified_diff(
            lines,
            patched,
            fromfile=f"a/{path.name}",
            tofile=f"b/{path.name}",
            lineterm="",
            n=CONTEXT_LINES,
        )
    )


# --------------------------------------------------------------------------
# Proposition de correction
# --------------------------------------------------------------------------

PATCH_SYSTEM_PROMPT = """Tu es un Senior Cybersecurity Engineer. On te donne \
une ligne de code vulnerable et son contexte. Tu proposes le remplacement de \
cette seule ligne.

Regles imperatives :
- Tu modifies UNE seule ligne : celle qui est signalee.
- `original_line` doit reproduire exactement la ligne actuelle, sans rien
  changer, indentation comprise.
- `replacement_line` conserve la meme indentation et le meme style.
- Tu n'ajoutes ni import, ni fonction, ni commentaire superflu.
- Si la correction ne peut pas tenir sur cette ligne, renvoie
  `replacement_line` vide et explique pourquoi.

Reponds exclusivement par un objet JSON avec les cles original_line,
replacement_line et explanation."""


async def _ask_patch(
    client: OpenAIClient,
    notification: AINotification,
    excerpt: str,
    current_line: str,
) -> PatchProposal:
    """Demande au modele la ligne de remplacement."""
    user_prompt = (
        f"Vulnerabilite : {notification.title} ({notification.classification})\n"
        f"Resume : {notification.summary}\n"
        f"Correction attendue : {notification.remediation_summary}\n\n"
        f"Fichier : {notification.affected_file}\n"
        f"Ligne a corriger : {notification.affected_line}\n\n"
        f"Ligne actuelle :\n{current_line}\n\n"
        f"Contexte :\n{excerpt}\n"
    )

    raw = await client.complete_json(PATCH_SYSTEM_PROMPT, user_prompt)

    try:
        return PatchProposal.model_validate(raw)
    except ValidationError as exc:
        raise AIResponseError(
            "Correction proposée inexploitable", detail=str(exc.errors()[:2])
        ) from exc


async def build_preview(
    notification: AINotification,
    client: Optional[OpenAIClient] = None,
) -> RemediationPreview:
    """Prepare la correction sans rien ecrire.

    Cette etape est purement en lecture : elle sert a montrer a
    l'utilisateur ce qui serait modifie, avant qu'il confirme.
    """
    manual_steps = notification.recommendations

    preview = RemediationPreview(
        notification_id=notification.id,
        alert_id=notification.alert_id,
        available=False,
        status=notification.remediation_status,
        remediation_type=notification.remediation_type,
        summary=notification.remediation_summary,
        file=notification.affected_file,
        line=notification.affected_line,
        manual_steps=manual_steps,
    )

    if not settings.ai_remediation_enabled:
        preview.blockers = ["La remédiation est désactivée (AI_REMEDIATION_ENABLED)."]
        return preview

    if not notification.remediation_available:
        preview.blockers = ["Aucune correction automatisable n'a été identifiée."]
        return preview

    if notification.remediation_type != "code_patch":
        preview.blockers = [
            "Cette correction n'est pas un patch de code : elle doit être "
            "appliquée manuellement en suivant les recommandations."
        ]
        return preview

    target, blockers = await asyncio.to_thread(resolve_target, notification.affected_file)
    if target is None:
        preview.blockers = blockers
        return preview

    lines = await asyncio.to_thread(_read_lines, target)
    line_number = notification.affected_line or 0

    if line_number < 1 or line_number > len(lines):
        preview.blockers = [
            f"La ligne {line_number} n'existe pas dans {target.name} "
            f"({len(lines)} lignes)."
        ]
        return preview

    current_line = lines[line_number - 1]
    excerpt = _excerpt(lines, line_number)

    try:
        proposal = await _ask_patch(client or get_openai_client(), notification, excerpt, current_line)
    except AIError as exc:
        preview.blockers = [f"Correction indisponible : {exc.message}"]
        return preview

    # Garde : le fichier a-t-il change depuis l'analyse ?
    if proposal.original_line.strip() and proposal.original_line.strip() != current_line.strip():
        preview.blockers = [
            "Le contenu de la ligne ne correspond plus à ce qui a été analysé : "
            "le fichier a probablement été modifié depuis."
        ]
        preview.original_excerpt = excerpt
        return preview

    if not proposal.replacement_line.strip():
        preview.blockers = [
            proposal.explanation
            or "Le modèle n'a pas pu produire une correction tenant sur une ligne."
        ]
        preview.original_excerpt = excerpt
        return preview

    preview.available = True
    preview.status = "awaiting_confirmation"
    preview.resolved_path = str(target)
    preview.original_excerpt = excerpt
    preview.proposed_excerpt = proposal.replacement_line
    preview.diff = await asyncio.to_thread(
        build_diff, target, lines, line_number, proposal.replacement_line
    )

    await asyncio.to_thread(
        store.update_notification_fields,
        notification.id,
        remediation_status="awaiting_confirmation",
        updated_at=_now_iso(),
    )
    await asyncio.to_thread(
        store.write_audit,
        "REMEDIATION_PROPOSED",
        notification.id,
        notification.alert_id,
        None,
        "agent-ia",
        str(target),
    )
    return preview


# --------------------------------------------------------------------------
# Application
# --------------------------------------------------------------------------


def _record_to_model(row: dict[str, Any]) -> RemediationRecord:
    return RemediationRecord(
        id=row["id"],
        notification_id=row["notification_id"],
        alert_id=row["alert_id"],
        status=row["status"],
        remediation_type=row["remediation_type"],
        summary=row["summary"] or "",
        file=row["file"],
        line=row["line"],
        diff=row["diff"],
        backup_path=row["backup_path"],
        error=row["error"],
        created_at=row["created_at"],
        applied_at=row["applied_at"],
        rolled_back_at=row["rolled_back_at"],
    )


def _apply_patch_sync(
    target: Path,
    line_number: int,
    replacement: str,
    expected_line: str,
) -> tuple[str, Optional[str]]:
    """Ecrit la correction. Retourne (diff, chemin de sauvegarde).

    Derniere verification juste avant l'ecriture : la ligne doit toujours
    correspondre. Sinon l'ecriture est refusee.
    """
    lines = _read_lines(target)

    if line_number < 1 or line_number > len(lines):
        raise RemediationError("La ligne visée n'existe plus dans le fichier.")

    if lines[line_number - 1].strip() != expected_line.strip():
        raise RemediationError(
            "Le fichier a changé depuis la proposition : correction annulée."
        )

    diff = build_diff(target, lines, line_number, replacement)

    backup_path: Optional[str] = None
    if settings.ai_remediation_backup:
        backup = target.with_suffix(
            target.suffix + f".bak-{datetime.now(timezone.utc):%Y%m%d%H%M%S}"
        )
        shutil.copy2(target, backup)
        backup_path = str(backup)

    lines[line_number - 1] = replacement
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return diff, backup_path


async def confirm(
    notification: AINotification,
    actor: str = "utilisateur",
    client: Optional[OpenAIClient] = None,
) -> RemediationRecord:
    """Applique la correction, apres confirmation explicite de l'utilisateur.

    L'appelant (la route) a deja verifie que l'utilisateur a confirme.
    """
    if not settings.ai_remediation_enabled:
        raise RemediationError("La remédiation est désactivée.")

    if notification.remediation_status in ("applied",):
        raise RemediationError("Cette correction a déjà été appliquée.")

    if notification.remediation_status in ("rejected", "cancelled"):
        raise RemediationError(
            "Cette correction est au statut "
            f"'{i18n.remediation_status_label(notification.remediation_status)}'."
        )

    preview = await build_preview(notification, client=client)

    if not preview.available or not preview.proposed_excerpt:
        reason = preview.blockers[0] if preview.blockers else "correction indisponible"
        await _fail(notification, reason, actor)
        raise RemediationError("Correction impossible", detail=reason)

    target = Path(preview.resolved_path)
    line_number = notification.affected_line or 0
    original_line = ""
    lines = await asyncio.to_thread(_read_lines, target)
    if 1 <= line_number <= len(lines):
        original_line = lines[line_number - 1]

    remediation_id = await asyncio.to_thread(
        store.insert_remediation,
        {
            "notification_id": notification.id,
            "alert_id": notification.alert_id,
            "status": "approved",
            "remediation_type": notification.remediation_type,
            "summary": notification.remediation_summary,
            "file": str(target),
            "line": line_number,
            "diff": preview.diff,
            "created_at": _now_iso(),
        },
    )

    await asyncio.to_thread(
        store.write_audit,
        "REMEDIATION_APPROVED",
        notification.id,
        notification.alert_id,
        remediation_id,
        actor,
        str(target),
    )

    try:
        diff, backup_path = await asyncio.to_thread(
            _apply_patch_sync,
            target,
            line_number,
            preview.proposed_excerpt,
            original_line,
        )
    except (RemediationError, OSError) as exc:
        message = getattr(exc, "message", str(exc))
        await asyncio.to_thread(
            store.update_remediation,
            remediation_id,
            status="failed",
            error=message,
        )
        await asyncio.to_thread(
            store.update_notification_fields,
            notification.id,
            remediation_status="failed",
            updated_at=_now_iso(),
        )
        await asyncio.to_thread(
            store.write_audit,
            "REMEDIATION_FAILED",
            notification.id,
            notification.alert_id,
            remediation_id,
            actor,
            str(target),
            "error",
            message,
        )
        raise RemediationError(
            "L'application de la correction a échoué", detail=message
        ) from exc

    now = _now_iso()
    await asyncio.to_thread(
        store.update_remediation,
        remediation_id,
        status="applied",
        diff=diff,
        backup_path=backup_path,
        applied_at=now,
    )
    await asyncio.to_thread(
        store.update_notification_fields,
        notification.id,
        remediation_status="applied",
        status="resolved",
        resolved_at=now,
        updated_at=now,
    )
    await asyncio.to_thread(
        store.write_audit,
        "REMEDIATION_APPLIED",
        notification.id,
        notification.alert_id,
        remediation_id,
        actor,
        str(target),
    )

    logger.info(
        "Correction appliquee : notification %s, fichier %s ligne %s",
        notification.id,
        target.name,
        line_number,
    )
    row = await asyncio.to_thread(store.get_remediation, remediation_id)
    return _record_to_model(row)


async def _fail(notification: AINotification, reason: str, actor: str) -> None:
    await asyncio.to_thread(
        store.write_audit,
        "REMEDIATION_FAILED",
        notification.id,
        notification.alert_id,
        None,
        actor,
        notification.affected_file,
        "error",
        reason,
    )


async def reject(
    notification: AINotification,
    reason: Optional[str] = None,
    actor: str = "utilisateur",
) -> AINotification:
    """L'utilisateur refuse la correction proposee."""
    now = _now_iso()

    await asyncio.to_thread(
        store.update_notification_fields,
        notification.id,
        remediation_status="rejected",
        updated_at=now,
    )
    await asyncio.to_thread(
        store.insert_remediation,
        {
            "notification_id": notification.id,
            "alert_id": notification.alert_id,
            "status": "rejected",
            "remediation_type": notification.remediation_type,
            "summary": reason or notification.remediation_summary,
            "file": notification.affected_file,
            "line": notification.affected_line,
            "created_at": now,
        },
    )
    await asyncio.to_thread(
        store.write_audit,
        "REMEDIATION_REJECTED",
        notification.id,
        notification.alert_id,
        None,
        actor,
        notification.affected_file,
        "ok",
        reason,
    )

    from app.ai import notifications as notifications_service

    return await notifications_service.get(notification.id)


async def rollback(remediation_id: int, actor: str = "utilisateur") -> RemediationRecord:
    """Restaure la sauvegarde prise avant l'application."""
    row = await asyncio.to_thread(store.get_remediation, remediation_id)
    if row is None:
        raise RemediationError("Remédiation introuvable")

    if row["status"] != "applied":
        raise RemediationError(
            "Seule une correction appliquée peut être annulée "
            f"(statut : {i18n.remediation_status_label(row['status'])})."
        )

    backup_path = row["backup_path"]
    if not backup_path or not Path(backup_path).exists():
        raise RemediationError("Aucune sauvegarde disponible pour cette correction.")

    target = Path(row["file"])
    try:
        await asyncio.to_thread(shutil.copy2, backup_path, target)
    except OSError as exc:
        await asyncio.to_thread(
            store.write_audit,
            "REMEDIATION_ROLLBACK_FAILED",
            row["notification_id"],
            row["alert_id"],
            remediation_id,
            actor,
            str(target),
            "error",
            str(exc),
        )
        raise RemediationError("Restauration impossible", detail=str(exc)) from exc

    now = _now_iso()
    await asyncio.to_thread(
        store.update_remediation, remediation_id, status="cancelled", rolled_back_at=now
    )
    await asyncio.to_thread(
        store.update_notification_fields,
        row["notification_id"],
        remediation_status="cancelled",
        status="acknowledged",
        updated_at=now,
    )
    await asyncio.to_thread(
        store.write_audit,
        "REMEDIATION_ROLLED_BACK",
        row["notification_id"],
        row["alert_id"],
        remediation_id,
        actor,
        str(target),
    )

    logger.info("Correction %s annulee, fichier restaure : %s", remediation_id, target)
    updated = await asyncio.to_thread(store.get_remediation, remediation_id)
    return _record_to_model(updated)


async def list_records(
    limit: int = 100, notification_id: Optional[int] = None
) -> list[RemediationRecord]:
    rows = await asyncio.to_thread(store.list_remediations, limit, notification_id)
    return [_record_to_model(row) for row in rows]


async def get_record(remediation_id: int) -> Optional[RemediationRecord]:
    row = await asyncio.to_thread(store.get_remediation, remediation_id)
    return _record_to_model(row) if row else None
