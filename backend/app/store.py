"""Persistance SQLite : alertes, etat de surveillance et notifications.

Toutes les fonctions sont synchrones (sqlite3 est bloquant). Le poller les
appelle via `asyncio.to_thread` pour ne jamais bloquer la boucle asyncio.
"""

import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from app.config import settings
from app.models import Alert, AlertSource, Rule

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    wazuh_id          TEXT    NOT NULL UNIQUE,
    timestamp         TEXT    NOT NULL,
    agent_id          TEXT,
    agent_name        TEXT,
    agent_ip          TEXT,
    rule_id           TEXT,
    rule_level        INTEGER NOT NULL DEFAULT 0,
    rule_description  TEXT,
    full_log          TEXT,
    location          TEXT,
    created_at        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp  ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_level ON alerts (rule_level);
CREATE INDEX IF NOT EXISTS idx_alerts_agent_id   ON alerts (agent_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts (created_at DESC);

CREATE TABLE IF NOT EXISTS monitoring_state (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications_sent (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    wazuh_id TEXT NOT NULL,
    channel  TEXT NOT NULL,
    status   TEXT NOT NULL DEFAULT 'sent',
    error    TEXT,
    sent_at  TEXT NOT NULL,
    UNIQUE (wazuh_id, channel)
);

CREATE INDEX IF NOT EXISTS idx_notifications_wazuh_id ON notifications_sent (wazuh_id);
CREATE INDEX IF NOT EXISTS idx_notifications_channel  ON notifications_sent (channel);

CREATE TABLE IF NOT EXISTS ai_analyses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    wazuh_id    TEXT NOT NULL UNIQUE,
    severity    TEXT NOT NULL,
    risk_score  INTEGER NOT NULL DEFAULT 0,
    analysis    TEXT NOT NULL,
    analyzed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ai_risk_score  ON ai_analyses (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_ai_severity    ON ai_analyses (severity);
CREATE INDEX IF NOT EXISTS idx_ai_analyzed_at ON ai_analyses (analyzed_at DESC);

CREATE TABLE IF NOT EXISTS ai_notifications (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id              TEXT NOT NULL UNIQUE,
    server_id             TEXT,
    server_name           TEXT,
    agent_id              TEXT,
    rule_id               TEXT,
    rule_level            INTEGER NOT NULL DEFAULT 0,
    alert_timestamp       TEXT,
    source                TEXT NOT NULL DEFAULT 'ia',
    title                 TEXT NOT NULL DEFAULT '',
    severity              TEXT NOT NULL,
    classification        TEXT NOT NULL DEFAULT 'unknown',
    risk_score            INTEGER NOT NULL DEFAULT 0,
    confidence            REAL NOT NULL DEFAULT 0,
    summary               TEXT DEFAULT '',
    why_dangerous         TEXT DEFAULT '',
    potential_impact      TEXT DEFAULT '[]',
    recommendations       TEXT DEFAULT '[]',
    notification_message  TEXT DEFAULT '',
    remediation_available  INTEGER NOT NULL DEFAULT 0,
    remediation_type      TEXT NOT NULL DEFAULT 'none',
    remediation_summary   TEXT DEFAULT '',
    remediation_status    TEXT NOT NULL DEFAULT 'not_available',
    affected_file         TEXT,
    affected_line         INTEGER,
    status                TEXT NOT NULL DEFAULT 'new',
    occurrences           INTEGER NOT NULL DEFAULT 1,
    created_at            TEXT NOT NULL,
    updated_at            TEXT,
    acknowledged_at       TEXT,
    resolved_at           TEXT,
    dismissed_at          TEXT
);

CREATE INDEX IF NOT EXISTS idx_notif_created  ON ai_notifications (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notif_severity ON ai_notifications (severity);
CREATE INDEX IF NOT EXISTS idx_notif_status   ON ai_notifications (status);
CREATE INDEX IF NOT EXISTS idx_notif_remstat  ON ai_notifications (remediation_status);
CREATE INDEX IF NOT EXISTS idx_notif_server   ON ai_notifications (server_name);

CREATE TABLE IF NOT EXISTS ai_remediations (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    notification_id  INTEGER NOT NULL,
    alert_id         TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',
    remediation_type TEXT NOT NULL DEFAULT 'none',
    summary          TEXT DEFAULT '',
    file             TEXT,
    line             INTEGER,
    diff             TEXT,
    backup_path      TEXT,
    error            TEXT,
    created_at       TEXT NOT NULL,
    applied_at       TEXT,
    rolled_back_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_remed_notif  ON ai_remediations (notification_id);
CREATE INDEX IF NOT EXISTS idx_remed_status ON ai_remediations (status);

CREATE TABLE IF NOT EXISTS ai_audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    action          TEXT NOT NULL,
    notification_id INTEGER,
    alert_id        TEXT,
    remediation_id  INTEGER,
    actor           TEXT NOT NULL DEFAULT 'utilisateur',
    target          TEXT,
    result          TEXT NOT NULL DEFAULT 'ok',
    error           TEXT,
    created_at      TEXT NOT NULL
);


CREATE INDEX IF NOT EXISTS idx_audit_created ON ai_audit_log (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_notif   ON ai_audit_log (notification_id);

-- --------------------------------------------------------------------
-- Analyse de code (extension VS Code). Tables independantes de la
-- chaine Wazuh : aucune cle etrangere vers alerts ou ai_notifications.
-- --------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS code_scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_uid        TEXT    NOT NULL UNIQUE,
    workspace       TEXT,
    -- Projet auquel ce scan appartient (phase 1). NULL pour un fichier
    -- ouvert hors de tout dossier, et pour les scans anterieurs.
    project_uid     TEXT,
    file_path       TEXT    NOT NULL,
    language        TEXT    NOT NULL DEFAULT 'other',
    content_hash    TEXT    NOT NULL,
    line_count      INTEGER NOT NULL DEFAULT 0,
    rules_version   TEXT    NOT NULL DEFAULT '',
    analysis_status TEXT    NOT NULL DEFAULT 'pending',
    analysis_error  TEXT,
    model           TEXT,
    created_at      TEXT    NOT NULL,
    analyzed_at     TEXT,
    -- Derniere fois que ce contenu a ete constate dans ce fichier : a la
    -- creation, puis a chaque scan servi depuis le cache pour le meme
    -- projet. Un fichier ramene a un contenu deja analyse ne cree aucune
    -- ligne ; sans ces deux colonnes, son dernier scan resterait l'ancien.
    last_seen_at    TEXT,
    -- Ordre de constatation, strictement croissant : departage deux scans
    -- d'un meme fichier quand l'horloge ne le peut pas. NULL = `id`.
    seen_order      INTEGER,
    -- Cle de cache : un meme contenu, dans un meme fichier, n'est
    -- analyse qu'une fois.
    UNIQUE (file_path, content_hash)
);

CREATE INDEX IF NOT EXISTS idx_code_scans_hash    ON code_scans (content_hash);
CREATE INDEX IF NOT EXISTS idx_code_scans_file    ON code_scans (file_path);
CREATE INDEX IF NOT EXISTS idx_code_scans_created ON code_scans (created_at DESC);

CREATE TABLE IF NOT EXISTS code_findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          INTEGER NOT NULL,
    finding_uid      TEXT    NOT NULL UNIQUE,
    rule_id          TEXT    NOT NULL,
    category         TEXT    NOT NULL DEFAULT 'unknown',
    cwe              TEXT,
    owasp            TEXT,
    severity         TEXT    NOT NULL DEFAULT 'MEDIUM',
    risk_score       INTEGER NOT NULL DEFAULT 0,
    confidence       REAL    NOT NULL DEFAULT 0,
    source           TEXT    NOT NULL DEFAULT 'rule',
    title            TEXT    DEFAULT '',
    explanation      TEXT    DEFAULT '',
    why_dangerous    TEXT    DEFAULT '',
    potential_impact TEXT    DEFAULT '[]',
    recommendations  TEXT    DEFAULT '[]',
    risk_factors     TEXT    DEFAULT '[]',
    line_start       INTEGER NOT NULL DEFAULT 1,
    line_end         INTEGER NOT NULL DEFAULT 1,
    column_start     INTEGER NOT NULL DEFAULT 0,
    column_end       INTEGER NOT NULL DEFAULT 0,
    snippet          TEXT    DEFAULT '',
    fix_available    INTEGER NOT NULL DEFAULT 0,
    fix_summary      TEXT    DEFAULT '',
    status           TEXT    NOT NULL DEFAULT 'open',
    decision_reason  TEXT,
    created_at       TEXT    NOT NULL,
    updated_at       TEXT,
    FOREIGN KEY (scan_id) REFERENCES code_scans (id)
);

CREATE INDEX IF NOT EXISTS idx_code_find_scan     ON code_findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_code_find_severity ON code_findings (severity);
CREATE INDEX IF NOT EXISTS idx_code_find_status   ON code_findings (status);
CREATE INDEX IF NOT EXISTS idx_code_find_created  ON code_findings (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_code_find_category ON code_findings (category);

CREATE TABLE IF NOT EXISTS code_fixes (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id        INTEGER NOT NULL,
    original_line     TEXT,
    replacement_line  TEXT,
    explanation       TEXT DEFAULT '',
    diff              TEXT,
    -- Trace : le backend n'ecrit jamais, c'est l'editeur qui applique.
    applied_in_editor INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES code_findings (id)
);

CREATE INDEX IF NOT EXISTS idx_code_fixes_finding ON code_fixes (finding_id);

-- --------------------------------------------------------------------
-- Contexte de projet (phase 1). Trois tables, aucune cle etrangere vers
-- la chaine Wazuh : le decouplage constate a la phase precedente est
-- conserve.
--
-- Ce qui est volontairement ABSENT de ces tables :
--   * le chemin absolu du workspace — `root_hash` le remplace ; un chemin
--     absolu revele le nom de l'utilisateur et l'arborescence du poste ;
--   * le contenu des fichiers — l'index porte une empreinte, jamais un
--     octet de code ;
--   * la valeur des secrets — les fichiers sensibles sont recenses par
--     chemin et par motif, jamais lus.
-- --------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS projects (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    project_uid      TEXT    NOT NULL UNIQUE,
    -- SHA-256 du chemin racine normalise. Identifie le projet de facon
    -- stable d'une session a l'autre sans stocker le chemin.
    root_hash        TEXT    NOT NULL UNIQUE,
    display_name     TEXT    NOT NULL DEFAULT '',
    project_types    TEXT    NOT NULL DEFAULT '[]',
    primary_language TEXT,
    languages        TEXT    NOT NULL DEFAULT '[]',
    frameworks       TEXT    NOT NULL DEFAULT '[]',
    file_count       INTEGER NOT NULL DEFAULT 0,
    indexed_count    INTEGER NOT NULL DEFAULT 0,
    truncated        INTEGER NOT NULL DEFAULT 0,
    has_git          INTEGER NOT NULL DEFAULT 0,
    -- Hote seul (« github.com »), jamais l'URL complete : une URL de
    -- remote peut porter un jeton d'acces.
    git_remote_host  TEXT,
    discovery_version TEXT   NOT NULL DEFAULT '',
    status           TEXT    NOT NULL DEFAULT 'ready',
    created_at       TEXT    NOT NULL,
    last_seen_at     TEXT    NOT NULL,
    last_discovery_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_projects_root ON projects (root_hash);
CREATE INDEX IF NOT EXISTS idx_projects_seen ON projects (last_seen_at DESC);

CREATE TABLE IF NOT EXISTS project_files (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id     INTEGER NOT NULL,
    -- Chemin RELATIF a la racine du projet, separateurs normalises.
    path           TEXT    NOT NULL,
    language       TEXT,
    -- source | manifest | config | infra | test | sensitive | other
    kind           TEXT    NOT NULL DEFAULT 'other',
    size           INTEGER NOT NULL DEFAULT 0,
    content_hash   TEXT,
    mtime          TEXT,
    indexed_at     TEXT    NOT NULL,
    UNIQUE (project_id, path),
    FOREIGN KEY (project_id) REFERENCES projects (id)
);

CREATE INDEX IF NOT EXISTS idx_project_files_kind ON project_files (project_id, kind);
CREATE INDEX IF NOT EXISTS idx_project_files_lang ON project_files (project_id, language);

-- --------------------------------------------------------------------
-- Securite projet (phase 2) : findings unifies et inventaire des
-- dependances.
--
-- AUCUNE cle etrangere vers la chaine Wazuh, et aucun appel Wazuh dans le
-- code qui remplit ces tables : secrets, dependances et vulnerabilites
-- fonctionnent avec Wazuh completement arrete.
--
-- Ce qui est volontairement ABSENT de `security_findings` :
--   * la valeur d'un secret — `evidence` est expurgee par
--     `app.security.redaction` AVANT d'arriver ici, et le modele la
--     reexpurge sans faire confiance a l'appelant ;
--   * le contenu du fichier — une ligne et une preuve expurgee suffisent
--     a retrouver le probleme dans l'editeur ;
--   * le chemin absolu — `file_path` est relatif a la racine du projet.
-- --------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS security_findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id       TEXT    NOT NULL UNIQUE,
    project_uid      TEXT    NOT NULL,
    -- SECRET | DEPENDENCY | CODE | CONFIGURATION | API | GIT
    category         TEXT    NOT NULL,
    severity         TEXT    NOT NULL DEFAULT 'MEDIUM',
    -- HIGH | MEDIUM | LOW. Distincte de la gravite : une detection
    -- incertaine d'un probleme grave reste grave.
    confidence       TEXT    NOT NULL DEFAULT 'MEDIUM',
    title            TEXT    NOT NULL DEFAULT '',
    description      TEXT    NOT NULL DEFAULT '',
    -- Chemin RELATIF a la racine du projet. NULL pour un finding qui ne
    -- porte pas sur un fichier (dependance transitive, par exemple).
    file_path        TEXT,
    line_start       INTEGER NOT NULL DEFAULT 0,
    line_end         INTEGER NOT NULL DEFAULT 0,
    -- Preuve EXPURGEE. Jamais la valeur reelle d'un secret.
    evidence         TEXT    NOT NULL DEFAULT '',
    remediation      TEXT    NOT NULL DEFAULT '',
    -- `references` est un mot reserve SQL : la colonne porte un autre nom.
    reference_links  TEXT    NOT NULL DEFAULT '[]',
    detection_engine TEXT    NOT NULL DEFAULT '',
    -- Empreinte stable du finding : elle permet a un second balayage de
    -- reconnaitre le meme probleme, donc de ne pas creer de doublon et de
    -- ne pas faire reapparaitre ce que l'utilisateur a ecarte. Ne porte
    -- aucune valeur de secret.
    fingerprint      TEXT    NOT NULL DEFAULT '',
    status           TEXT    NOT NULL DEFAULT 'open',
    created_at       TEXT    NOT NULL,
    updated_at       TEXT
);

CREATE INDEX IF NOT EXISTS idx_secfind_project  ON security_findings (project_uid);
CREATE INDEX IF NOT EXISTS idx_secfind_category ON security_findings (project_uid, category);
CREATE INDEX IF NOT EXISTS idx_secfind_severity ON security_findings (project_uid, severity);
CREATE INDEX IF NOT EXISTS idx_secfind_status   ON security_findings (project_uid, status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_secfind_fingerprint
    ON security_findings (project_uid, category, fingerprint);

-- --------------------------------------------------------------------
-- Assistant IA de securite (phase 6) : explications mises en cache.
--
-- Table SEPAREE de `security_findings`, et c'est le point essentiel de
-- cette phase : aucune ecriture de l'assistant ne touche la table des
-- findings. Le moteur deterministe reste la source de verite, et
-- l'explication vit a cote — supprimer toutes les lignes de cette table
-- ne change pas un seul finding, ni sa gravite, ni son statut.
--
-- `finding_signature` est une empreinte du finding TEL QU'IL ETAIT quand
-- l'explication a ete produite. Un finding requalifie par un nouveau
-- balayage (gravite differente, preuve differente) invalide donc son
-- explication au lieu d'afficher un texte qui ne lui correspond plus.
--
-- Ce qui est volontairement ABSENT : la valeur d'un secret (le payload est
-- construit depuis un finding deja expurge) et le contenu d'un fichier.
-- --------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS security_ai_analyses (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    project_uid       TEXT    NOT NULL,
    finding_id        TEXT    NOT NULL,
    model             TEXT    NOT NULL DEFAULT '',
    -- Empreinte du finding au moment de l'analyse. Voir ci-dessus.
    finding_signature TEXT    NOT NULL DEFAULT '',
    -- `SecurityFindingAiAnalysis` serialise.
    payload           TEXT    NOT NULL,
    created_at        TEXT    NOT NULL,
    UNIQUE (project_uid, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_secai_project ON security_ai_analyses (project_uid);
CREATE INDEX IF NOT EXISTS idx_secai_created ON security_ai_analyses (created_at DESC);

CREATE TABLE IF NOT EXISTS project_dependencies (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id   INTEGER NOT NULL,
    name         TEXT    NOT NULL,
    ecosystem    TEXT    NOT NULL DEFAULT 'unknown',
    -- Peut etre vide : un manifeste declare souvent une contrainte
    -- (« ^1.2.0 ») et non une version. Une contrainte n'est pas
    -- interrogeable, et la dependance est alors comptee NON VERIFIEE.
    version      TEXT    NOT NULL DEFAULT '',
    direct       INTEGER NOT NULL DEFAULT 1,
    manifest     TEXT    NOT NULL DEFAULT '',
    -- manifest | lockfile. Un lockfile donne une version exacte, donc
    -- interrogeable ; c'est la difference qui decide de la couverture.
    source       TEXT    NOT NULL DEFAULT 'manifest',
    vulnerable   INTEGER NOT NULL DEFAULT 0,
    -- Le fournisseur a-t-il reellement repondu pour cette dependance ?
    -- Sans ce drapeau, « aucune vulnerabilite trouvee » et « personne n'a
    -- regarde » seraient indiscernables en base.
    verified     INTEGER NOT NULL DEFAULT 0,
    indexed_at   TEXT    NOT NULL,
    UNIQUE (project_id, ecosystem, name, version, manifest),
    FOREIGN KEY (project_id) REFERENCES projects (id)
);

CREATE INDEX IF NOT EXISTS idx_projdeps_project ON project_dependencies (project_id);
CREATE INDEX IF NOT EXISTS idx_projdeps_eco     ON project_dependencies (project_id, ecosystem);
CREATE INDEX IF NOT EXISTS idx_projdeps_vuln    ON project_dependencies (project_id, vulnerable);

CREATE TABLE IF NOT EXISTS project_context (
    project_id      INTEGER PRIMARY KEY,
    -- Instantane JSON du contexte tel qu'il a ete renvoye a l'extension.
    -- Relire le meme objet evite qu'un second calcul produise une reponse
    -- differente de la premiere.
    payload         TEXT    NOT NULL,
    computed_at     TEXT    NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects (id)
);
"""

# Colonnes attendues dans `alerts` : sert a detecter un schema obsolete.
_EXPECTED_ALERT_COLUMNS = {
    "wazuh_id",
    "timestamp",
    "agent_id",
    "agent_name",
    "rule_id",
    "rule_level",
    "rule_description",
    "full_log",
    "location",
    "created_at",
}

# Cles utilisees dans monitoring_state.
STATE_CURSOR = "alerts_cursor"
STATE_LAST_SCAN = "last_scan"
STATE_LAST_ALERT = "last_alert"
STATE_RUNNING = "running"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """Ouvre une connexion SQLite avec des lignes accessibles par nom."""
    Path(settings.database_path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(settings.database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        yield connection
        connection.commit()
    finally:
        connection.close()


def _migrate_legacy_alerts(connection: sqlite3.Connection) -> None:
    """Supprime une table `alerts` issue d'un schema anterieur.

    Le schema initial du squelette stockait `id`/`level`/`description` ;
    il est remplace par `wazuh_id`/`rule_level`/`rule_description`.
    """
    tables = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'"
    ).fetchone()
    if tables is None:
        return

    columns = {row["name"] for row in connection.execute("PRAGMA table_info(alerts)")}
    if _EXPECTED_ALERT_COLUMNS.issubset(columns):
        return

    rows = connection.execute("SELECT COUNT(*) AS total FROM alerts").fetchone()["total"]
    logger.warning(
        "Table 'alerts' au format obsolete (%s ligne(s)) : recreation du schema", rows
    )
    connection.execute("DROP TABLE alerts")


# Colonnes ajoutees apres coup a `ai_notifications` : elles portent
# l'identite Wazuh de l'alerte (regle, niveau, date) et l'origine de la
# notification. Ajout purement additif : aucune donnee existante n'est
# touchee, les bases deja en service sont completees au demarrage.
_NOTIFICATION_COLUMNS: tuple[tuple[str, str], ...] = (
    ("agent_id", "TEXT"),
    ("rule_id", "TEXT"),
    ("rule_level", "INTEGER NOT NULL DEFAULT 0"),
    ("alert_timestamp", "TEXT"),
    ("source", "TEXT NOT NULL DEFAULT 'ia'"),
    # Etat de l'analyse IA, distinct de `status` (qui dit seulement si
    # l'utilisateur a vu la notification) : pending, analyzing, analyzed,
    # failed. Une notification creee sur le niveau Wazuh nait `pending`.
    ("analysis_status", "TEXT NOT NULL DEFAULT 'pending'"),
    ("analysis_error", "TEXT"),
    ("analyzed_at", "TEXT"),
    # Description Wazuh d'origine, conservee telle quelle pour le diagnostic.
    ("wazuh_description", "TEXT"),
)

# Colonnes ajoutees a `code_scans` par la phase 1.
#
# Migration additive volontairement : une colonne nullable ne detruit
# aucun finding existant, et un retour arriere se contente de l'ignorer.
# La cle d'unicite `(file_path, content_hash)` n'est **pas** touchee — la
# reconstruire demanderait de recreer la table, pour un gain de cache qui
# n'est pas l'objet de cette phase (voir la limite F3 du rapport).
_CODE_SCAN_COLUMNS: tuple[tuple[str, str], ...] = (
    # Projet auquel le scan appartient. NULL pour les scans anterieurs a
    # la phase 1 et pour un fichier ouvert hors de tout dossier.
    ("project_uid", "TEXT"),
    # Dernier scan d'un fichier (phase 8) : voir `mark_code_scan_seen`.
    # NULL pour les scans anterieurs, qui retombent sur `created_at`/`id`.
    ("last_seen_at", "TEXT"),
    ("seen_order", "INTEGER"),
)


def _add_missing_columns(
    connection: sqlite3.Connection,
    table: str,
    columns: tuple[tuple[str, str], ...],
) -> set[str]:
    """Ajoute les colonnes absentes d'une table (migration idempotente).

    Retourne les colonnes reellement creees : l'appelant peut alors lancer
    une reprise de donnees une seule fois.
    """
    existing = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
    added: set[str] = set()
    for name, definition in columns:
        if name in existing:
            continue
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
        added.add(name)
        logger.info("Colonne %s.%s ajoutee", table, name)
    return added


def _backfill_analysis_status(connection: sqlite3.Connection) -> None:
    """Renseigne l'etat d'analyse des notifications existantes.

    Executee une seule fois, a la creation de la colonne. Une notification
    est consideree comme analysee si une analyse IA existe reellement pour
    son alerte : ni le statut de lecture, ni la simple existence de la
    notification ne suffisent.
    """
    connection.execute(
        """
        UPDATE ai_notifications
           SET analysis_status = 'analyzed',
               analyzed_at = COALESCE(analyzed_at, updated_at, created_at)
         WHERE alert_id IN (SELECT wazuh_id FROM ai_analyses)
        """
    )
    connection.execute(
        "UPDATE ai_notifications SET analysis_status = 'pending' "
        "WHERE analysis_status IS NULL OR analysis_status = ''"
    )
    logger.info("Etat d'analyse des notifications existantes recalcule")


def _backfill_wazuh_description(connection: sqlite3.Connection) -> None:
    """Recupere la description Wazuh d'origine des notifications anciennes.

    Avant l'ajout de la colonne, le titre d'une notification issue du
    niveau Wazuh *etait* la description brute : on la conserve donc telle
    quelle, sans rien reecrire.
    """
    connection.execute(
        "UPDATE ai_notifications SET wazuh_description = title "
        "WHERE wazuh_description IS NULL AND source = 'wazuh'"
    )


def _redact_stored_snippets(connection: sqlite3.Connection) -> None:
    """Expurge les extraits enregistres avant que le moteur de code ne
    masque les cles AWS, GitHub et Slack.

    Ces extraits ont pu recopier en clair la cle meme que la regle
    SECRET002 signalait. Seules les lignes candidates sont relues ; une
    ligne deja propre n'est pas reecrite. Idempotent.
    """
    # Import differe : le moteur de regles depend du sanitizer IA, pas
    # l'inverse.
    from app.code.rules import redact_snippet

    rows = connection.execute(
        "SELECT id, snippet FROM code_findings WHERE snippet LIKE '%AKIA%' "
        "OR snippet LIKE '%ASIA%' OR snippet LIKE '%ABIA%' OR snippet LIKE '%ACCA%' "
        "OR snippet LIKE '%gh%\\_%' ESCAPE '\\' OR snippet LIKE '%xox%-%'"
    ).fetchall()
    if rows:
        # Sans elle, l'ancien contenu d'une cellule reecrite reste lisible
        # dans le fichier : la cle serait expurgee des lignes, pas du disque.
        connection.execute("PRAGMA secure_delete = ON")
    cleaned = 0
    for row in rows:
        redacted = redact_snippet(row["snippet"])
        if redacted != row["snippet"]:
            connection.execute(
                "UPDATE code_findings SET snippet = ? WHERE id = ?", (redacted, row["id"])
            )
            cleaned += 1
    if cleaned:
        logger.info("%s extrait(s) de finding expurge(s) a posteriori", cleaned)


def init_db() -> None:
    """Cree le schema si necessaire (appele au demarrage de FastAPI)."""
    with get_connection() as connection:
        _migrate_legacy_alerts(connection)
        connection.executescript(SCHEMA)
        added = _add_missing_columns(
            connection, "ai_notifications", _NOTIFICATION_COLUMNS
        )
        if "analysis_status" in added:
            _backfill_analysis_status(connection)
        if "wazuh_description" in added:
            _backfill_wazuh_description(connection)
        # Base creee avant la phase 1 : la colonne manque, on l'ajoute.
        # Sur une base neuve, SCHEMA l'a deja posee et cet appel ne fait
        # rien. L'index vient apres, quand la colonne existe a coup sur.
        _add_missing_columns(connection, "code_scans", _CODE_SCAN_COLUMNS)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_code_scans_project "
            "ON code_scans (project_uid)"
        )
        _redact_stored_snippets(connection)
    logger.info("Base SQLite prete : %s", settings.database_path)


# --------------------------------------------------------------------------
# Alertes
# --------------------------------------------------------------------------


def _row_to_alert(row: sqlite3.Row) -> Alert:
    return Alert(
        id=row["wazuh_id"],
        timestamp=row["timestamp"],
        agent=AlertSource(
            id=row["agent_id"], name=row["agent_name"], ip=row["agent_ip"]
        ),
        rule=Rule(
            id=row["rule_id"],
            level=row["rule_level"] or 0,
            description=row["rule_description"] or "",
        ),
        full_log=row["full_log"],
        location=row["location"],
    )


def save_alert(alert: Alert) -> bool:
    """Enregistre une alerte. Retourne False si elle existait deja.

    La contrainte UNIQUE sur `wazuh_id` garantit qu'une alerte n'est jamais
    ajoutee deux fois, meme en cas de chevauchement temporel du poller.
    """
    with get_connection() as connection:
        return _insert_alert(connection, alert)


def _insert_alert(connection: sqlite3.Connection, alert: Alert) -> bool:
    cursor = connection.execute(
        """
        INSERT OR IGNORE INTO alerts (
            wazuh_id, timestamp, agent_id, agent_name, agent_ip,
            rule_id, rule_level, rule_description, full_log, location, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert.id,
            alert.timestamp,
            alert.agent.id,
            alert.agent.name,
            alert.agent.ip,
            alert.rule.id,
            alert.rule.level,
            alert.rule.description,
            alert.full_log,
            alert.location,
            _now_iso(),
        ),
    )
    return cursor.rowcount > 0


def save_alerts(alerts: list[Alert]) -> list[Alert]:
    """Enregistre un lot d'alertes et retourne uniquement les nouvelles."""
    if not alerts:
        return []

    inserted: list[Alert] = []
    with get_connection() as connection:
        for alert in alerts:
            if not alert.id:
                logger.debug("Alerte sans _id ignoree")
                continue
            if _insert_alert(connection, alert):
                inserted.append(alert)
    return inserted


def alert_exists(wazuh_id: str) -> bool:
    """Vrai si l'alerte est deja persistee."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT 1 FROM alerts WHERE wazuh_id = ? LIMIT 1", (wazuh_id,)
        ).fetchone()
        return row is not None


def list_alerts(
    limit: int = 50, min_level: int = 0, agent_id: Optional[str] = None
) -> list[Alert]:
    """Retourne les dernieres alertes persistees, les plus recentes d'abord.

    `agent_id` reste facultatif : sans lui, les alertes de tous les agents
    sont renvoyees, quel que soit leur systeme d'exploitation.
    """
    query = "SELECT * FROM alerts WHERE rule_level >= ?"
    params: list[Any] = [min_level]

    if agent_id:
        query += " AND agent_id = ?"
        params.append(agent_id)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with get_connection() as connection:
        rows = connection.execute(query, params).fetchall()
        return [_row_to_alert(row) for row in rows]


def list_alert_agents() -> list[dict[str, Any]]:
    """Agents presents dans les alertes persistees (pour les filtres).

    Aucune liste codee en dur : la vue se construit a partir de ce que
    Wazuh a reellement remonte, donc tout nouvel agent apparait seul.
    """
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT agent_id,
                   MAX(agent_name) AS agent_name,
                   COUNT(*)        AS alerts
            FROM alerts
            WHERE agent_id IS NOT NULL AND agent_id <> ''
            GROUP BY agent_id
            ORDER BY agent_id
            """
        ).fetchall()
        return [_row_to_dict(row) for row in rows]


def count_alerts(min_level: int = 0) -> int:
    """Nombre d'alertes persistees (optionnellement au-dessus d'un niveau)."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM alerts WHERE rule_level >= ?", (min_level,)
        ).fetchone()
        return int(row["total"])


def latest_alert_timestamp() -> Optional[str]:
    """Timestamp de l'alerte la plus recente en base (curseur de repli)."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT MAX(timestamp) AS ts FROM alerts"
        ).fetchone()
        return row["ts"]


def alerts_after(wazuh_id: str, limit: int = 50) -> list[Alert]:
    """Alertes enregistrees apres celle-ci, dans l'ordre d'insertion.

    Sert au rejeu SSE apres une reconnexion (`Last-Event-ID`). Si
    l'identifiant est inconnu, la liste est vide : on ne rejoue jamais tout
    l'historique par accident.
    """
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM alerts
            WHERE id > (SELECT id FROM alerts WHERE wazuh_id = ?)
            ORDER BY id ASC
            LIMIT ?
            """,
            (wazuh_id, limit),
        ).fetchall()
        return [_row_to_alert(row) for row in rows]


def known_alert_ids(limit: int = 2000) -> list[str]:
    """Derniers identifiants Wazuh connus (amorce du cache de dedoublonnage)."""
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT wazuh_id FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [row["wazuh_id"] for row in rows]


def count_similar_alerts(
    rule_id: Optional[str], agent_id: Optional[str], hours: int = 24
) -> int:
    """Alertes de meme regle et meme agent sur la periode donnee.

    Sert de facteur "repetition" dans l'evaluation du risque.
    """
    if not rule_id:
        return 0

    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS total FROM alerts
            WHERE rule_id = ?
              AND (? IS NULL OR agent_id = ?)
              AND created_at >= ?
            """,
            (rule_id, agent_id, agent_id, since),
        ).fetchone()
        return int(row["total"])


def get_alert(wazuh_id: str) -> Optional[Alert]:
    """Retrouve une alerte persistee par son identifiant Wazuh."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM alerts WHERE wazuh_id = ?", (wazuh_id,)
        ).fetchone()
        return _row_to_alert(row) if row else None


# --------------------------------------------------------------------------
# Analyses IA (cache : une alerte n'est analysee qu'une fois)
# --------------------------------------------------------------------------


def save_ai_analysis(
    wazuh_id: str, severity: str, risk_score: int, payload: str, analyzed_at: str
) -> None:
    """Enregistre (ou remplace) l'analyse d'une alerte."""
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO ai_analyses (wazuh_id, severity, risk_score, analysis, analyzed_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(wazuh_id) DO UPDATE SET
                severity    = excluded.severity,
                risk_score  = excluded.risk_score,
                analysis    = excluded.analysis,
                analyzed_at = excluded.analyzed_at
            """,
            (wazuh_id, severity, risk_score, payload, analyzed_at),
        )


def get_ai_analysis(wazuh_id: str) -> Optional[str]:
    """Analyse deja calculee pour cette alerte, si elle existe."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT analysis FROM ai_analyses WHERE wazuh_id = ?", (wazuh_id,)
        ).fetchone()
        return row["analysis"] if row else None


def list_ai_analyses(
    limit: int = 50, severity: Optional[str] = None, min_score: int = 0
) -> list[str]:
    """Analyses les plus recentes, filtrees si besoin."""
    query = "SELECT analysis FROM ai_analyses WHERE risk_score >= ?"
    params: list[Any] = [min_score]

    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())

    query += " ORDER BY analyzed_at DESC LIMIT ?"
    params.append(limit)

    with get_connection() as connection:
        return [row["analysis"] for row in connection.execute(query, params)]


def ai_analysis_stats() -> dict[str, Any]:
    """Compteurs par severite et score moyen."""
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS analyzed,
                   COALESCE(AVG(risk_score), 0) AS average,
                   SUM(severity = 'LOW')      AS low,
                   SUM(severity = 'MEDIUM')   AS medium,
                   SUM(severity = 'HIGH')     AS high,
                   SUM(severity = 'CRITICAL') AS critical
              FROM ai_analyses
            """
        ).fetchone()

        return {
            "analyzed": int(row["analyzed"] or 0),
            "average_risk_score": round(float(row["average"] or 0), 1),
            "low": int(row["low"] or 0),
            "medium": int(row["medium"] or 0),
            "high": int(row["high"] or 0),
            "critical": int(row["critical"] or 0),
        }


def analyzed_alert_ids(limit: int = 500) -> set[str]:
    """Identifiants deja analyses (amorce du cache memoire)."""
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT wazuh_id FROM ai_analyses ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return {row["wazuh_id"] for row in rows}


# --------------------------------------------------------------------------
# Notifications IA (alertes HIGH / CRITICAL)
# --------------------------------------------------------------------------


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def insert_notification(payload: dict[str, Any]) -> int:
    """Cree une notification et retourne son identifiant."""
    columns = ", ".join(payload)
    markers = ", ".join("?" for _ in payload)

    with get_connection() as connection:
        cursor = connection.execute(
            f"INSERT INTO ai_notifications ({columns}) VALUES ({markers})",
            tuple(payload.values()),
        )
        return int(cursor.lastrowid)


def get_notification_by_alert(alert_id: str) -> Optional[dict[str, Any]]:
    """Notification existante pour cette alerte (deduplication)."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM ai_notifications WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        return _row_to_dict(row) if row else None


def find_recent_notification(
    agent_id: Optional[str],
    rule_id: Optional[str],
    since: str,
) -> Optional[dict[str, Any]]:
    """Derniere notification pour ce couple agent + regle depuis `since`.

    Sert au cooldown : une meme regle qui se repete sur un meme serveur ne
    doit pas produire une avalanche de notifications. Le filtre reste
    volontairement etroit (agent ET regle) pour ne jamais masquer un
    incident different survenu au meme moment.
    """
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT * FROM ai_notifications
            WHERE agent_id IS ? AND rule_id IS ? AND created_at >= ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (agent_id, rule_id, since),
        ).fetchone()
        return _row_to_dict(row) if row else None


def get_notification(notification_id: int) -> Optional[dict[str, Any]]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM ai_notifications WHERE id = ?", (notification_id,)
        ).fetchone()
        return _row_to_dict(row) if row else None


def touch_notification(notification_id: int, updated_at: str) -> int:
    """Alerte deja notifiee : on incremente le compteur d'occurrences."""
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE ai_notifications
               SET occurrences = occurrences + 1, updated_at = ?
             WHERE id = ?
            """,
            (updated_at, notification_id),
        )
        row = connection.execute(
            "SELECT occurrences FROM ai_notifications WHERE id = ?", (notification_id,)
        ).fetchone()
        return int(row["occurrences"]) if row else 1


def update_notification_fields(notification_id: int, **fields: Any) -> None:
    """Mise a jour ciblee (statut, remediation_status, horodatages)."""
    if not fields:
        return

    assignments = ", ".join(f"{name} = ?" for name in fields)
    with get_connection() as connection:
        connection.execute(
            f"UPDATE ai_notifications SET {assignments} WHERE id = ?",
            (*fields.values(), notification_id),
        )


def list_notifications(
    limit: int = 100,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    remediation_status: Optional[str] = None,
    analysis_status: Optional[str] = None,
    server: Optional[str] = None,
    classification: Optional[str] = None,
    remediation_available: Optional[bool] = None,
    since: Optional[str] = None,
    search: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Historique filtre des notifications."""
    query = "SELECT * FROM ai_notifications WHERE 1 = 1"
    params: list[Any] = []

    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())
    if status:
        query += " AND status = ?"
        params.append(status)
    if remediation_status:
        query += " AND remediation_status = ?"
        params.append(remediation_status)
    if analysis_status:
        query += " AND analysis_status = ?"
        params.append(analysis_status)
    if server:
        query += " AND (server_name = ? OR server_id = ?)"
        params.extend([server, server])
    if classification:
        query += " AND classification = ?"
        params.append(classification)
    if remediation_available is not None:
        query += " AND remediation_available = ?"
        params.append(1 if remediation_available else 0)
    if since:
        query += " AND created_at >= ?"
        params.append(since)
    if search:
        query += (
            " AND (title LIKE ? OR summary LIKE ? OR classification LIKE ?"
            " OR server_name LIKE ? OR affected_file LIKE ?)"
        )
        pattern = f"%{search}%"
        params.extend([pattern] * 5)

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    with get_connection() as connection:
        return [_row_to_dict(row) for row in connection.execute(query, params)]


def notification_stats() -> dict[str, int]:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(status = 'new') AS pending,
                   SUM(remediation_available = 1) AS remediable
              FROM ai_notifications
            """
        ).fetchone()
        return {
            "notifications": int(row["total"] or 0),
            "notifications_new": int(row["pending"] or 0),
            "remediations_available": int(row["remediable"] or 0),
        }


# --------------------------------------------------------------------------
# Remediations
# --------------------------------------------------------------------------


def insert_remediation(payload: dict[str, Any]) -> int:
    columns = ", ".join(payload)
    markers = ", ".join("?" for _ in payload)

    with get_connection() as connection:
        cursor = connection.execute(
            f"INSERT INTO ai_remediations ({columns}) VALUES ({markers})",
            tuple(payload.values()),
        )
        return int(cursor.lastrowid)


def update_remediation(remediation_id: int, **fields: Any) -> None:
    if not fields:
        return

    assignments = ", ".join(f"{name} = ?" for name in fields)
    with get_connection() as connection:
        connection.execute(
            f"UPDATE ai_remediations SET {assignments} WHERE id = ?",
            (*fields.values(), remediation_id),
        )


def get_remediation(remediation_id: int) -> Optional[dict[str, Any]]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM ai_remediations WHERE id = ?", (remediation_id,)
        ).fetchone()
        return _row_to_dict(row) if row else None


def list_remediations(
    limit: int = 100, notification_id: Optional[int] = None
) -> list[dict[str, Any]]:
    query = "SELECT * FROM ai_remediations WHERE 1 = 1"
    params: list[Any] = []

    if notification_id is not None:
        query += " AND notification_id = ?"
        params.append(notification_id)

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    with get_connection() as connection:
        return [_row_to_dict(row) for row in connection.execute(query, params)]


# --------------------------------------------------------------------------
# Journal d'audit
# --------------------------------------------------------------------------


def write_audit(
    action: str,
    notification_id: Optional[int] = None,
    alert_id: Optional[str] = None,
    remediation_id: Optional[int] = None,
    actor: str = "utilisateur",
    target: Optional[str] = None,
    result: str = "ok",
    error: Optional[str] = None,
) -> int:
    """Trace une action de remediation. Ne leve jamais."""
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO ai_audit_log
                (action, notification_id, alert_id, remediation_id,
                 actor, target, result, error, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                action,
                notification_id,
                alert_id,
                remediation_id,
                actor,
                target,
                result,
                error,
                _now_iso(),
            ),
        )
        return int(cursor.lastrowid)


def list_audit(limit: int = 100, notification_id: Optional[int] = None) -> list[dict[str, Any]]:
    query = "SELECT * FROM ai_audit_log WHERE 1 = 1"
    params: list[Any] = []

    if notification_id is not None:
        query += " AND notification_id = ?"
        params.append(notification_id)

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    with get_connection() as connection:
        return [_row_to_dict(row) for row in connection.execute(query, params)]


# --------------------------------------------------------------------------
# Etat de la surveillance
# --------------------------------------------------------------------------


def set_state(key: str, value: Optional[Any]) -> None:
    """Enregistre une valeur d'etat (curseur, dernier scan...)."""
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO monitoring_state (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                           updated_at = excluded.updated_at
            """,
            (key, None if value is None else str(value), _now_iso()),
        )


def get_state(key: str, default: Optional[str] = None) -> Optional[str]:
    """Lit une valeur d'etat."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT value FROM monitoring_state WHERE key = ?", (key,)
        ).fetchone()
        return default if row is None or row["value"] is None else row["value"]


def all_state() -> dict[str, Optional[str]]:
    """Tout l'etat de surveillance persiste."""
    with get_connection() as connection:
        rows = connection.execute("SELECT key, value FROM monitoring_state").fetchall()
        return {row["key"]: row["value"] for row in rows}


# --------------------------------------------------------------------------
# Notifications envoyees
# --------------------------------------------------------------------------


def mark_notification(
    wazuh_id: str,
    channel: str,
    status: str = "sent",
    error: Optional[str] = None,
) -> bool:
    """Trace l'envoi d'une notification. False si deja envoyee sur ce canal.

    Sert de garde anti-doublon : une alerte critique n'est notifiee qu'une
    seule fois par canal, meme si le poller la revoit.
    """
    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO notifications_sent
                (wazuh_id, channel, status, error, sent_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (wazuh_id, channel, status, error, _now_iso()),
        )
        return cursor.rowcount > 0


def was_notified(wazuh_id: str, channel: str) -> bool:
    """Vrai si une notification a deja ete tracee pour ce couple."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT 1 FROM notifications_sent WHERE wazuh_id = ? AND channel = ? LIMIT 1",
            (wazuh_id, channel),
        ).fetchone()
        return row is not None


def update_notification(
    wazuh_id: str, channel: str, status: str, error: Optional[str] = None
) -> None:
    """Met a jour le resultat d'une notification (succes / echec)."""
    with get_connection() as connection:
        connection.execute(
            """
            UPDATE notifications_sent
               SET status = ?, error = ?, sent_at = ?
             WHERE wazuh_id = ? AND channel = ?
            """,
            (status, error, _now_iso(), wazuh_id, channel),
        )


def count_notifications(channel: Optional[str] = None) -> int:
    """Nombre de notifications tracees."""
    with get_connection() as connection:
        if channel is None:
            row = connection.execute(
                "SELECT COUNT(*) AS total FROM notifications_sent"
            ).fetchone()
        else:
            row = connection.execute(
                "SELECT COUNT(*) AS total FROM notifications_sent WHERE channel = ?",
                (channel,),
            ).fetchone()
        return int(row["total"])


# --------------------------------------------------------------------------
# Analyse de code (extension VS Code)
# --------------------------------------------------------------------------
#
# Aucune de ces fonctions ne touche aux tables Wazuh. Le contenu des
# fichiers analyses n'est JAMAIS stocke : seuls son empreinte, sa taille
# et les extraits de ligne (deja expurges) le sont.


def insert_code_scan(payload: dict[str, Any]) -> int:
    """Enregistre un scan et retourne son identifiant interne."""
    columns = ", ".join(payload)
    markers = ", ".join("?" for _ in payload)

    with get_connection() as connection:
        cursor = connection.execute(
            f"INSERT INTO code_scans ({columns}) VALUES ({markers})",
            tuple(payload.values()),
        )
        return int(cursor.lastrowid)


def mark_code_scan_seen(scan_id: int, seen_at: str) -> None:
    """Fait de ce scan le dernier constat de son fichier.

    Appelee a la creation d'un scan et quand un scan est resservi depuis le
    cache. La cle de cache `(file_path, content_hash)` interdit une seconde
    ligne pour un contenu deja vu : un fichier corrige en revenant a une
    version anterieure garderait sinon pour « dernier scan » celui du
    contenu fautif, et la posture comme le controle CI compteraient un
    probleme disparu.

    `seen_order` est calcule dans la meme instruction : l'horloge ne
    departage pas deux scans rapproches, un compteur si.
    """
    with get_connection() as connection:
        connection.execute(
            "UPDATE code_scans SET last_seen_at = ?, seen_order = ("
            "    SELECT COALESCE(MAX(COALESCE(seen_order, id)), 0) + 1 FROM code_scans"
            ") WHERE id = ?",
            (seen_at, scan_id),
        )


# Dernier scan de chaque fichier d'un projet. `seen_order` NULL (scan
# anterieur a la colonne) retombe sur `id`, l'ordre utilise jusque-la.
_LATEST_CODE_SCANS = (
    "SELECT id FROM ("
    "    SELECT id, ROW_NUMBER() OVER ("
    "        PARTITION BY project_uid, file_path"
    "        ORDER BY COALESCE(seen_order, id) DESC"
    "    ) AS position"
    "    FROM code_scans WHERE project_uid = ?"
    ") WHERE position = 1"
)


def get_code_scan_by_hash(file_path: str, content_hash: str) -> Optional[dict[str, Any]]:
    """Scan deja effectue pour ce couple fichier + empreinte (cache)."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM code_scans WHERE file_path = ? AND content_hash = ?",
            (file_path, content_hash),
        ).fetchone()
        return _row_to_dict(row) if row else None


def delete_code_scan(scan_id: int) -> None:
    """Supprime un scan devenu obsolete, ses findings et leurs correctifs.

    Sert a un seul cas : le catalogue de regles a change depuis que ce
    scan a ete enregistre. Son resultat ne decrit plus ce que l'analyse
    trouverait aujourd'hui, et la contrainte UNIQUE (file_path,
    content_hash) interdit d'en enregistrer un second pour le meme
    contenu. La place est donc liberee avant la reanalyse.

    Les trois tables sont videes dans l'ordre impose par les cles
    etrangeres, dans une seule transaction.
    """
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM code_fixes WHERE finding_id IN ("
            "    SELECT id FROM code_findings WHERE scan_id = ?"
            ")",
            (scan_id,),
        )
        connection.execute("DELETE FROM code_findings WHERE scan_id = ?", (scan_id,))
        connection.execute("DELETE FROM code_scans WHERE id = ?", (scan_id,))


def get_code_scan_by_id(scan_id: int) -> Optional[dict[str, Any]]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM code_scans WHERE id = ?", (scan_id,)
        ).fetchone()
        return _row_to_dict(row) if row else None


def get_code_scan(scan_uid: str) -> Optional[dict[str, Any]]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM code_scans WHERE scan_uid = ?", (scan_uid,)
        ).fetchone()
        return _row_to_dict(row) if row else None


def update_code_scan_fields(scan_id: int, **fields: Any) -> None:
    if not fields:
        return

    assignments = ", ".join(f"{name} = ?" for name in fields)
    with get_connection() as connection:
        connection.execute(
            f"UPDATE code_scans SET {assignments} WHERE id = ?",
            (*fields.values(), scan_id),
        )


def insert_code_finding(payload: dict[str, Any]) -> int:
    columns = ", ".join(payload)
    markers = ", ".join("?" for _ in payload)

    with get_connection() as connection:
        cursor = connection.execute(
            f"INSERT INTO code_findings ({columns}) VALUES ({markers})",
            tuple(payload.values()),
        )
        return int(cursor.lastrowid)


def list_code_findings_by_scan(scan_id: int) -> list[dict[str, Any]]:
    with get_connection() as connection:
        return [
            _row_to_dict(row)
            for row in connection.execute(
                "SELECT * FROM code_findings WHERE scan_id = ? "
                "ORDER BY line_start ASC, id ASC",
                (scan_id,),
            )
        ]


def get_code_finding(finding_uid: str) -> Optional[dict[str, Any]]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM code_findings WHERE finding_uid = ?", (finding_uid,)
        ).fetchone()
        return _row_to_dict(row) if row else None


def update_code_finding_fields(finding_id: int, **fields: Any) -> None:
    """Mise a jour ciblee. Un finding n'est jamais supprime physiquement."""
    if not fields:
        return

    assignments = ", ".join(f"{name} = ?" for name in fields)
    with get_connection() as connection:
        connection.execute(
            f"UPDATE code_findings SET {assignments} WHERE id = ?",
            (*fields.values(), finding_id),
        )


def list_code_findings(
    limit: int = 100,
    offset: int = 0,
    file_path: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    since: Optional[str] = None,
    project_uid: Optional[str] = None,
    current_only: bool = False,
) -> list[dict[str, Any]]:
    """Historique filtre des findings, joint au scan pour le fichier.

    `project_uid` est un parametre nomme place en dernier : les appels
    positionnels existants gardent exactement le meme sens. Quand il est
    fourni, seuls les findings de ce projet ressortent — c'est ce filtre
    qui empeche deux projets partageant `src/app.py` de se contaminer.

    `current_only`, avec `project_uid`, ne garde que le dernier scan de
    chaque fichier. Un dernier scan sans finding n'a aucune ligne dans cet
    historique : le client ne peut pas le deviner, et reprendrait le scan
    fautif precedent.
    """
    query = (
        "SELECT f.*, s.scan_uid AS scan_uid, s.file_path AS scan_file_path "
        "FROM code_findings f JOIN code_scans s ON s.id = f.scan_id WHERE 1 = 1"
    )
    params: list[Any] = []

    if project_uid:
        query += " AND s.project_uid = ?"
        params.append(project_uid)
        if current_only:
            query += f" AND s.id IN ({_LATEST_CODE_SCANS})"
            params.append(project_uid)
    if file_path:
        query += " AND s.file_path = ?"
        params.append(file_path)
    if severity:
        query += " AND f.severity = ?"
        params.append(severity.upper())
    if status:
        query += " AND f.status = ?"
        params.append(status)
    if category:
        query += " AND f.category = ?"
        params.append(category)
    if since:
        query += " AND f.created_at >= ?"
        params.append(since)

    query += " ORDER BY f.created_at DESC, f.id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_connection() as connection:
        return [_row_to_dict(row) for row in connection.execute(query, params)]


def count_code_findings(
    file_path: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    category: Optional[str] = None,
    since: Optional[str] = None,
) -> int:
    query = (
        "SELECT COUNT(*) AS total FROM code_findings f "
        "JOIN code_scans s ON s.id = f.scan_id WHERE 1 = 1"
    )
    params: list[Any] = []

    if file_path:
        query += " AND s.file_path = ?"
        params.append(file_path)
    if severity:
        query += " AND f.severity = ?"
        params.append(severity.upper())
    if status:
        query += " AND f.status = ?"
        params.append(status)
    if category:
        query += " AND f.category = ?"
        params.append(category)
    if since:
        query += " AND f.created_at >= ?"
        params.append(since)

    with get_connection() as connection:
        return int(connection.execute(query, params).fetchone()["total"] or 0)


def insert_code_fix(payload: dict[str, Any]) -> int:
    columns = ", ".join(payload)
    markers = ", ".join("?" for _ in payload)

    with get_connection() as connection:
        cursor = connection.execute(
            f"INSERT INTO code_fixes ({columns}) VALUES ({markers})",
            tuple(payload.values()),
        )
        return int(cursor.lastrowid)


def code_stats() -> dict[str, Any]:
    """Vue globale de l'analyse de code."""
    with get_connection() as connection:
        scans = connection.execute(
            "SELECT COUNT(*) AS scans, COUNT(DISTINCT file_path) AS files "
            "FROM code_scans"
        ).fetchone()

        totals = connection.execute(
            """
            SELECT COUNT(*) AS findings,
                   SUM(status = 'open')      AS open_count,
                   SUM(status = 'dismissed') AS dismissed_count,
                   SUM(status = 'fixed')     AS fixed_count,
                   SUM(severity = 'CRITICAL') AS critical,
                   SUM(severity = 'HIGH')     AS high,
                   SUM(severity = 'MEDIUM')   AS medium,
                   SUM(severity = 'LOW')      AS low
              FROM code_findings
            """
        ).fetchone()

        categories = connection.execute(
            "SELECT category, COUNT(*) AS total FROM code_findings "
            "GROUP BY category ORDER BY total DESC"
        ).fetchall()

    return {
        "scans": int(scans["scans"] or 0),
        "files": int(scans["files"] or 0),
        "findings": int(totals["findings"] or 0),
        "open": int(totals["open_count"] or 0),
        "dismissed": int(totals["dismissed_count"] or 0),
        "fixed": int(totals["fixed_count"] or 0),
        "critical": int(totals["critical"] or 0),
        "high": int(totals["high"] or 0),
        "medium": int(totals["medium"] or 0),
        "low": int(totals["low"] or 0),
        "by_category": {row["category"]: int(row["total"]) for row in categories},
    }


# --------------------------------------------------------------------------
# Contexte de projet (phase 1)
# --------------------------------------------------------------------------
#
# Le backend ne parcourt jamais le disque du developpeur : c'est
# l'extension qui decouvre, et ces fonctions enregistrent ce qu'elle
# soumet. Rien ici ne lit un fichier.


def upsert_project(payload: dict[str, Any]) -> dict[str, Any]:
    """Cree ou met a jour un projet, identifie par son `root_hash`.

    `root_hash` plutot que `project_uid` comme cle de reconciliation : un
    meme dossier reouvert doit retrouver son projet, meme si l'extension a
    perdu l'identifiant entre deux sessions.
    """
    root_hash = payload["root_hash"]

    with get_connection() as connection:
        existing = connection.execute(
            "SELECT * FROM projects WHERE root_hash = ?", (root_hash,)
        ).fetchone()

        if existing is None:
            columns = ", ".join(payload)
            markers = ", ".join("?" for _ in payload)
            connection.execute(
                f"INSERT INTO projects ({columns}) VALUES ({markers})",
                tuple(payload.values()),
            )
        else:
            # `project_uid` et `created_at` ne sont jamais reecrits : des
            # findings et des scans y font deja reference.
            updatable = {
                name: value
                for name, value in payload.items()
                if name not in {"project_uid", "root_hash", "created_at"}
            }
            if updatable:
                assignments = ", ".join(f"{name} = ?" for name in updatable)
                connection.execute(
                    f"UPDATE projects SET {assignments} WHERE root_hash = ?",
                    (*updatable.values(), root_hash),
                )

        row = connection.execute(
            "SELECT * FROM projects WHERE root_hash = ?", (root_hash,)
        ).fetchone()

    return _row_to_dict(row)


def get_project_by_uid(project_uid: str) -> Optional[dict[str, Any]]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM projects WHERE project_uid = ?", (project_uid,)
        ).fetchone()
        return _row_to_dict(row) if row else None


def get_project_by_root_hash(root_hash: str) -> Optional[dict[str, Any]]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM projects WHERE root_hash = ?", (root_hash,)
        ).fetchone()
        return _row_to_dict(row) if row else None


def touch_project(project_uid: str, seen_at: str) -> None:
    """Note qu'un projet vient d'etre ouvert, sans rien recalculer."""
    with get_connection() as connection:
        connection.execute(
            "UPDATE projects SET last_seen_at = ? WHERE project_uid = ?",
            (seen_at, project_uid),
        )


def replace_project_files(project_id: int, files: list[dict[str, Any]]) -> int:
    """Remplace l'index d'un projet par celui qui vient d'etre soumis.

    Remplacement et non fusion : un fichier supprime du projet doit
    disparaitre de l'index, sinon le decompte affiche devient faux et la
    couverture annoncee ne correspond plus a la realite.

    Une seule transaction : un index a moitie ecrit serait pire que
    l'ancien.
    """
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM project_files WHERE project_id = ?", (project_id,)
        )
        if not files:
            return 0

        connection.executemany(
            "INSERT INTO project_files "
            "(project_id, path, language, kind, size, content_hash, mtime, indexed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    project_id,
                    entry["path"],
                    entry.get("language"),
                    entry.get("kind", "other"),
                    int(entry.get("size", 0)),
                    entry.get("content_hash"),
                    entry.get("mtime"),
                    entry["indexed_at"],
                )
                for entry in files
            ],
        )
    return len(files)


def count_project_files(project_id: int) -> int:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM project_files WHERE project_id = ?",
            (project_id,),
        ).fetchone()
        return int(row["total"] or 0)


def list_project_files(
    project_id: int,
    kind: Optional[str] = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    query = "SELECT * FROM project_files WHERE project_id = ?"
    params: list[Any] = [project_id]

    if kind:
        query += " AND kind = ?"
        params.append(kind)

    query += " ORDER BY path ASC LIMIT ?"
    params.append(limit)

    with get_connection() as connection:
        return [_row_to_dict(row) for row in connection.execute(query, params)]


def project_language_counts(project_id: int) -> dict[str, int]:
    """Nombre de fichiers indexes par langage, pour ce projet seulement."""
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT language, COUNT(*) AS total FROM project_files "
            "WHERE project_id = ? AND language IS NOT NULL AND language != '' "
            "GROUP BY language ORDER BY total DESC",
            (project_id,),
        ).fetchall()
    return {row["language"]: int(row["total"]) for row in rows}


def save_project_context(project_id: int, payload: str, computed_at: str) -> None:
    """Conserve l'instantane du contexte renvoye a l'extension."""
    with get_connection() as connection:
        connection.execute(
            "INSERT INTO project_context (project_id, payload, computed_at) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT (project_id) DO UPDATE SET "
            "payload = excluded.payload, computed_at = excluded.computed_at",
            (project_id, payload, computed_at),
        )


def get_project_context(project_id: int) -> Optional[dict[str, Any]]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM project_context WHERE project_id = ?", (project_id,)
        ).fetchone()
        return _row_to_dict(row) if row else None


# --------------------------------------------------------------------------
# Securite projet (phase 2) : findings unifies
# --------------------------------------------------------------------------
#
# Rien ici n'appelle Wazuh, et rien ici ne lit un fichier : ces fonctions
# enregistrent ce que l'extension a constate sur le poste du developpeur.
#
# `evidence` arrive deja expurgee (`app.security.redaction`) et repasse par
# le validateur du modele avant d'atteindre ces fonctions. Aucune valeur de
# secret n'est ecrite dans ces tables.


def sync_security_findings(
    project_uid: str,
    category: str,
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Aligne les findings d'une categorie sur le dernier balayage.

    Ni un remplacement brutal, ni une fusion naive :

    - un finding **deja connu** (meme empreinte) conserve son `status` et
      son `created_at`. Sans cela, un balayage ferait reapparaitre ce que
      l'utilisateur a ecarte comme faux positif — le plus sur moyen de
      rendre un outil de securite inutilisable ;
    - un finding **disparu** du balayage est supprime : le probleme a ete
      corrige, et le laisser affiche serait faux ;
    - tout se joue dans une seule transaction : un etat a moitie ecrit
      serait pire que l'ancien.

    Retourne le detail de l'operation, pour le journal et les tests.
    """
    now = _now_iso()
    seen = {row["fingerprint"] for row in rows}

    inserted = 0
    updated = 0

    with get_connection() as connection:
        existing = {
            row["fingerprint"]: dict(row)
            for row in connection.execute(
                "SELECT * FROM security_findings "
                "WHERE project_uid = ? AND category = ?",
                (project_uid, category),
            )
        }

        obsolete = [
            fingerprint for fingerprint in existing if fingerprint not in seen
        ]
        if obsolete:
            connection.executemany(
                "DELETE FROM security_findings "
                "WHERE project_uid = ? AND category = ? AND fingerprint = ?",
                [(project_uid, category, fingerprint) for fingerprint in obsolete],
            )

        for row in rows:
            known = existing.get(row["fingerprint"])
            if known is None:
                connection.execute(
                    "INSERT INTO security_findings "
                    "(finding_id, project_uid, category, severity, confidence, "
                    " title, description, file_path, line_start, line_end, "
                    " evidence, remediation, reference_links, detection_engine, "
                    " fingerprint, status, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        row["finding_id"],
                        project_uid,
                        category,
                        row.get("severity", "MEDIUM"),
                        row.get("confidence", "MEDIUM"),
                        row.get("title", ""),
                        row.get("description", ""),
                        row.get("file_path"),
                        int(row.get("line_start", 0)),
                        int(row.get("line_end", 0)),
                        row.get("evidence", ""),
                        row.get("remediation", ""),
                        row.get("reference_links", "[]"),
                        row.get("detection_engine", ""),
                        row["fingerprint"],
                        row.get("status", "open"),
                        now,
                        None,
                    ),
                )
                inserted += 1
                continue

            # Le contenu est rafraichi (une gravite peut changer avec la
            # base de vulnerabilites), la decision de l'utilisateur non.
            connection.execute(
                "UPDATE security_findings SET "
                "severity = ?, confidence = ?, title = ?, description = ?, "
                "file_path = ?, line_start = ?, line_end = ?, evidence = ?, "
                "remediation = ?, reference_links = ?, detection_engine = ?, "
                "updated_at = ? "
                "WHERE id = ?",
                (
                    row.get("severity", "MEDIUM"),
                    row.get("confidence", "MEDIUM"),
                    row.get("title", ""),
                    row.get("description", ""),
                    row.get("file_path"),
                    int(row.get("line_start", 0)),
                    int(row.get("line_end", 0)),
                    row.get("evidence", ""),
                    row.get("remediation", ""),
                    row.get("reference_links", "[]"),
                    row.get("detection_engine", ""),
                    now,
                    int(known["id"]),
                ),
            )
            updated += 1

    return {
        "inserted": inserted,
        "updated": updated,
        "removed": len(obsolete),
        "total": len(rows),
    }


def list_security_findings(
    project_uid: str,
    category: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Findings d'un projet, du plus grave au plus localise.

    Le filtre par projet n'est pas optionnel : sans lui, deux projets
    analyses par le meme backend melangeraient leurs findings, et un
    `src/config.py` afficherait les secrets de l'autre.
    """
    query = "SELECT * FROM security_findings WHERE project_uid = ?"
    params: list[Any] = [project_uid]

    if category:
        query += " AND category = ?"
        params.append(category)
    if status:
        query += " AND status = ?"
        params.append(status)
    if severity:
        query += " AND severity = ?"
        params.append(severity)

    query += (
        " ORDER BY CASE severity "
        "WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
        "WHEN 'MEDIUM' THEN 2 ELSE 3 END, "
        "file_path ASC, line_start ASC LIMIT ?"
    )
    params.append(limit)

    with get_connection() as connection:
        return [_row_to_dict(row) for row in connection.execute(query, params)]


def get_security_finding(finding_id: str) -> Optional[dict[str, Any]]:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM security_findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        return _row_to_dict(row) if row else None


def count_security_findings(
    project_uid: str, category: Optional[str] = None
) -> dict[str, int]:
    """Repartition par gravite des findings ouverts d'un projet."""
    query = (
        "SELECT severity, COUNT(*) AS total FROM security_findings "
        "WHERE project_uid = ? AND status = 'open'"
    )
    params: list[Any] = [project_uid]
    if category:
        query += " AND category = ?"
        params.append(category)
    query += " GROUP BY severity"

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    with get_connection() as connection:
        for row in connection.execute(query, params):
            counts[str(row["severity"]).upper()] = int(row["total"] or 0)
    return counts


def count_files_with_security_findings(project_uid: str, category: str) -> int:
    """Nombre de fichiers distincts portant au moins un finding ouvert."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT COUNT(DISTINCT file_path) AS total FROM security_findings "
            "WHERE project_uid = ? AND category = ? AND status = 'open' "
            "AND file_path IS NOT NULL",
            (project_uid, category),
        ).fetchone()
        return int(row["total"] or 0)


def delete_security_findings(project_uid: str, category: Optional[str] = None) -> int:
    """Efface les findings d'un projet. Sert au changement de projet et aux tests."""
    query = "DELETE FROM security_findings WHERE project_uid = ?"
    params: list[Any] = [project_uid]
    if category:
        query += " AND category = ?"
        params.append(category)

    with get_connection() as connection:
        cursor = connection.execute(query, params)
        return int(cursor.rowcount or 0)


# --------------------------------------------------------------------------
# Posture de securite (phase 8) — lectures seules
# --------------------------------------------------------------------------
#
# Aucune table nouvelle : la posture se lit dans les tables existantes.


def project_code_posture(project_uid: str) -> dict[str, Any]:
    """Findings de code ouverts du DERNIER scan de chaque fichier du projet.

    Un fichier reanalyse garde ses scans precedents en base ; les compter
    ferait apparaitre des problemes deja corriges. Seul le scan le plus
    recent de chaque fichier fait foi — la meme regle que la vue de
    l'extension (`latestScanPerFile`). « Recent » se lit dans l'ordre de
    constatation (`mark_code_scan_seen`), pas dans l'ordre de creation : un
    fichier revenu a un contenu deja analyse ne cree aucun scan.

    Un fichier supprime n'est plus jamais reanalyse : son dernier scan
    compterait indefiniment, et bloquerait la CI sur un fichier disparu.
    Il est ecarte quand un index COMPLET, soumis APRES ce scan, ne le
    contient plus — seul cas ou l'absence prouve la suppression. Un index
    tronque, ou un fichier analyse apres le dernier index, garde ses
    findings : dans le doute, on compte.
    """
    with get_connection() as connection:
        project = connection.execute(
            "SELECT id, truncated, last_discovery_at FROM projects WHERE project_uid = ?",
            (project_uid,),
        ).fetchone()
        prune = bool(project and not project["truncated"] and project["last_discovery_at"])
        current = (
            "WITH current AS ("
            "    SELECT id, file_path, COALESCE(last_seen_at, created_at) AS seen_at "
            f"    FROM code_scans WHERE id IN ({_LATEST_CODE_SCANS})"
            "), present AS ("
            "    SELECT * FROM current WHERE NOT ("
            "        ? AND seen_at < ? AND file_path NOT IN ("
            "            SELECT path FROM project_files WHERE project_id = ?"
            "        )"
            "    )"
            ") "
        )
        params = (
            project_uid,
            1 if prune else 0,
            project["last_discovery_at"] if prune else "",
            int(project["id"]) if project else -1,
        )
        summary = connection.execute(
            current + "SELECT COUNT(*) AS files, MAX(seen_at) AS last_scan FROM present",
            params,
        ).fetchone()
        rows = connection.execute(
            current
            + "SELECT f.finding_uid, f.severity, f.category, f.title, f.line_start, "
            "f.created_at, p.file_path AS file_path "
            "FROM code_findings f JOIN present p ON p.id = f.scan_id "
            "WHERE f.status = 'open'",
            params,
        ).fetchall()
    return {
        "files_scanned": int(summary["files"] or 0),
        "last_scan": summary["last_scan"],
        "findings": [_row_to_dict(row) for row in rows],
    }


def count_indexed_files_for_languages(project_id: int, languages: list[str]) -> int:
    """Fichiers source ou de test indexes, dans les langages donnes."""
    if not languages:
        return 0
    marks = ", ".join("?" for _ in languages)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM project_files WHERE project_id = ? "
            f"AND kind IN ('source', 'test') AND language IN ({marks})",
            (project_id, *languages),
        ).fetchone()
    return int(row["total"] or 0)


# --------------------------------------------------------------------------
# Assistant IA de securite (phase 6)
# --------------------------------------------------------------------------
#
# Aucune de ces fonctions n'ecrit dans `security_findings`. C'est
# verifiable en lisant les requetes ci-dessous, et un test le verifie sur
# le code source du paquet : l'assistant explique, il ne decide pas.


def save_security_ai_analysis(
    project_uid: str,
    finding_id: str,
    model: str,
    finding_signature: str,
    payload: str,
) -> None:
    """Enregistre (ou remplace) l'explication IA d'un finding.

    `INSERT ... ON CONFLICT` plutot qu'un `DELETE` suivi d'un `INSERT` :
    une explication reste lisible pendant qu'une nouvelle est calculee.
    """
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO security_ai_analyses
                (project_uid, finding_id, model, finding_signature,
                 payload, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (project_uid, finding_id) DO UPDATE SET
                model = excluded.model,
                finding_signature = excluded.finding_signature,
                payload = excluded.payload,
                created_at = excluded.created_at
            """,
            (project_uid, finding_id, model, finding_signature, payload, _now_iso()),
        )


def get_security_ai_analysis(
    project_uid: str, finding_id: str
) -> Optional[dict[str, Any]]:
    """Explication deja calculee pour ce finding de ce projet.

    Le filtre porte sur les deux colonnes, jamais sur `finding_id` seul :
    deux projets analyses par le meme backend ne doivent pas pouvoir se
    servir l'explication de l'autre.
    """
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM security_ai_analyses "
            "WHERE project_uid = ? AND finding_id = ?",
            (project_uid, finding_id),
        ).fetchone()
        return _row_to_dict(row) if row else None


def count_security_ai_analyses(project_uid: str) -> int:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM security_ai_analyses "
            "WHERE project_uid = ?",
            (project_uid,),
        ).fetchone()
        return int(row["total"] or 0)


def delete_security_ai_analyses(project_uid: str) -> int:
    """Efface les explications d'un projet. Les findings, eux, restent.

    Sert au changement de projet et aux tests. C'est la demonstration la
    plus directe de la separation : cette fonction vide le cache IA sans
    qu'aucun finding ne bouge.
    """
    with get_connection() as connection:
        cursor = connection.execute(
            "DELETE FROM security_ai_analyses WHERE project_uid = ?", (project_uid,)
        )
        return int(cursor.rowcount or 0)


# --------------------------------------------------------------------------
# Securite projet (phase 2) : inventaire des dependances
# --------------------------------------------------------------------------


def replace_project_dependencies(
    project_id: int, dependencies: list[dict[str, Any]]
) -> int:
    """Remplace l'inventaire d'un projet par celui du dernier releve.

    Remplacement et non fusion, pour la meme raison que l'index des
    fichiers : une dependance retiree du projet doit disparaitre du
    decompte, sinon le nombre affiche cesse de decrire le projet reel.
    """
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM project_dependencies WHERE project_id = ?", (project_id,)
        )
        if not dependencies:
            return 0

        connection.executemany(
            "INSERT OR REPLACE INTO project_dependencies "
            "(project_id, name, ecosystem, version, direct, manifest, source, "
            " vulnerable, verified, indexed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    project_id,
                    entry["name"],
                    entry.get("ecosystem", "unknown"),
                    entry.get("version", ""),
                    1 if entry.get("direct", True) else 0,
                    entry.get("manifest", ""),
                    entry.get("source", "manifest"),
                    1 if entry.get("vulnerable") else 0,
                    1 if entry.get("verified") else 0,
                    entry["indexed_at"],
                )
                for entry in dependencies
            ],
        )
    return len(dependencies)


def list_project_dependencies(
    project_id: int, limit: int = 5000
) -> list[dict[str, Any]]:
    with get_connection() as connection:
        return [
            _row_to_dict(row)
            for row in connection.execute(
                "SELECT * FROM project_dependencies WHERE project_id = ? "
                "ORDER BY ecosystem ASC, name ASC, version ASC LIMIT ?",
                (project_id, limit),
            )
        ]


def dependency_ecosystem_counts(project_id: int) -> list[dict[str, Any]]:
    """Volumes par ecosysteme, avec la part reellement verifiee.

    `verified` est compte separement de `total` : l'ecart entre les deux
    est la zone d'ombre, et c'est elle qu'il faut pouvoir afficher.
    """
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT ecosystem, "
            "COUNT(*) AS total, "
            "SUM(CASE WHEN direct = 1 THEN 1 ELSE 0 END) AS direct, "
            "SUM(CASE WHEN vulnerable = 1 THEN 1 ELSE 0 END) AS vulnerable, "
            "SUM(CASE WHEN verified = 1 THEN 1 ELSE 0 END) AS verified "
            "FROM project_dependencies WHERE project_id = ? "
            "GROUP BY ecosystem ORDER BY total DESC, ecosystem ASC",
            (project_id,),
        ).fetchall()

    return [
        {
            "ecosystem": row["ecosystem"],
            "total": int(row["total"] or 0),
            "direct": int(row["direct"] or 0),
            "vulnerable": int(row["vulnerable"] or 0),
            "verified": int(row["verified"] or 0),
        }
        for row in rows
    ]


def dependency_totals(project_id: int) -> dict[str, int]:
    """Totaux de l'inventaire : direct, transitif, vulnerable, non verifie."""
    with get_connection() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN direct = 1 THEN 1 ELSE 0 END) AS direct, "
            "SUM(CASE WHEN vulnerable = 1 THEN 1 ELSE 0 END) AS vulnerable, "
            "SUM(CASE WHEN verified = 1 THEN 1 ELSE 0 END) AS verified "
            "FROM project_dependencies WHERE project_id = ?",
            (project_id,),
        ).fetchone()

    total = int(row["total"] or 0)
    direct = int(row["direct"] or 0)
    verified = int(row["verified"] or 0)
    return {
        "total": total,
        "direct": direct,
        "transitive": total - direct,
        "vulnerable": int(row["vulnerable"] or 0),
        "verified": verified,
        # Jamais deduit comme « sain » : c'est exactement ce que personne
        # n'a pu regarder.
        "unverified": total - verified,
    }
