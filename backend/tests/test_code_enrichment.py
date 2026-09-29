"""Enrichissement IA des findings de code (phase 3).

Aucun appel reseau : le transport HTTP d'OpenAI est simule avec
`httpx.MockTransport`, comme partout ailleurs dans la suite. **Aucun test
n'exige de cle OpenAI.**

Deux garanties verifiees en priorite :

1. enrichissement desactive -> **aucune** requete ne part vers OpenAI ;
2. enrichissement en echec -> le scan le dit, et n'invente aucun resultat.
"""

import asyncio
import json

import httpx
import pytest

from app import store
from app.ai.openai_client import OpenAIClient
from app.code import analyzer, scanner
from app.code.schemas import CodeScanRequest, content_hash_of
from app.config import settings
from app.notifier import stream

VULNERABLE = (
    "def get_user(user_id):\n"
    '    query = "SELECT * FROM users WHERE id=" + user_id\n'
    "    return db.execute(query)\n"
)

SECRET_CODE = 'API_KEY = "sk-abcdefghijklmnopqrstuvwxyz0123456789"\n'

VERDICT = {
    "category": "sql_injection",
    "severity": "CRITICAL",
    "risk_score": 92,
    "confidence": 0.9,
    "false_positive": False,
    "title": "Injection SQL confirmée dans la requête utilisateur",
    "explanation": "La valeur user_id est concaténée sans échappement.",
    "why_dangerous": "Un attaquant peut lire toute la table users.",
    "potential_impact": ["Exfiltration de la base"],
    "recommendations": ["Utiliser une requête paramétrée"],
    "risk_factors": ["Entrée utilisateur directe"],
    "fix_available": False,
    "fix_summary": "",
}


def request_for(content: str = VULNERABLE, **overrides) -> CodeScanRequest:
    payload = {
        "file_path": "src/api/users.py",
        "language": "python",
        "content": content,
        "content_hash": content_hash_of(content),
        "workspace": "projet",
        "ai_enrichment": True,
    }
    payload.update(overrides)
    return CodeScanRequest(**payload)


class OpenAISpy:
    """Faux transport OpenAI : compte les appels et capture les prompts."""

    def __init__(self, handler=None):
        self.calls = 0
        self.prompts: list[dict] = []
        self._handler = handler

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        body = json.loads(request.content)
        self.prompts.append(
            {
                "system": body["messages"][0]["content"],
                "user": body["messages"][1]["content"],
            }
        )
        if self._handler is not None:
            return self._handler(request)
        return answer(VERDICT)


def answer(payload: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status,
        json={
            "model": "gpt-4o-mini",
            "usage": {"total_tokens": 300},
            "choices": [
                {"message": {"content": json.dumps(payload, ensure_ascii=False)}}
            ],
        },
    )


@pytest.fixture
def spy(monkeypatch):
    """Branche un client OpenAI simule et renvoie l'espion."""

    def install(handler=None) -> OpenAISpy:
        watcher = OpenAISpy(handler)
        client = OpenAIClient()
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(watcher))
        monkeypatch.setattr(analyzer, "get_openai_client", lambda: client)
        return watcher

    return install


@pytest.fixture
def sse_events(monkeypatch):
    """Capture les evenements pousses aux clients connectes.

    `project_uid` est accepte parce que la signature de `stream.publish`
    le porte depuis la phase 0. Il n'est pas verifie ici : le cloisonnement
    par projet a ses propres tests (tests/test_stream_isolation.py), qui
    exercent le vrai diffuseur plutot qu'un double.
    """
    captured: list = []

    async def capture(event, event_id=None, project_uid=None):
        captured.append(event)
        return 1

    monkeypatch.setattr(stream, "publish", capture)
    return captured


async def drain() -> None:
    """Attend la fin des taches d'enrichissement detachees."""
    for _ in range(20):
        pending = [task for task in scanner._background if not task.done()]
        if not pending:
            break
        await asyncio.gather(*pending, return_exceptions=True)


# --------------------------------------------------------------------------
# Enrichissement desactive : aucun appel OpenAI
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_par_defaut_aucun_appel_openai(spy, monkeypatch):
    """Configuration par defaut du projet : CODE_AI_ENRICHMENT_ENABLED=false."""
    monkeypatch.setattr(settings, "code_ai_enrichment_enabled", False)
    monkeypatch.setattr(settings, "openai_api_key", "sk-test")
    watcher = spy()

    result = await scanner.scan(request_for(ai_enrichment=True))
    await drain()

    assert watcher.calls == 0, "aucune requete ne doit partir vers OpenAI"
    assert result.analysis_status == "analyzed"
    assert result.ai_enrichment_requested is True
    assert result.ai_enrichment_applied is False
    assert result.findings[0].source == "rule"


@pytest.mark.asyncio
async def test_sans_cle_api_aucun_appel_openai(spy, monkeypatch):
    """L'activation seule ne suffit pas : il faut aussi une cle."""
    monkeypatch.setattr(settings, "code_ai_enrichment_enabled", True)
    monkeypatch.setattr(settings, "openai_api_key", "")
    watcher = spy()

    result = await scanner.scan(request_for())
    await drain()

    assert watcher.calls == 0
    assert result.analysis_status == "analyzed"
    assert result.ai_enrichment_applied is False


@pytest.mark.asyncio
async def test_client_refusant_l_enrichissement_n_appelle_pas_openai(spy, monkeypatch):
    """Backend activé, mais l'extension demande explicitement `false`."""
    monkeypatch.setattr(settings, "code_ai_enrichment_enabled", True)
    monkeypatch.setattr(settings, "openai_api_key", "sk-test")
    watcher = spy()

    result = await scanner.scan(request_for(ai_enrichment=False))
    await drain()

    assert watcher.calls == 0
    assert result.analysis_status == "analyzed"
    assert result.ai_enrichment_requested is False


@pytest.mark.asyncio
async def test_un_fichier_sans_finding_ne_declenche_aucun_appel(spy, monkeypatch):
    monkeypatch.setattr(settings, "code_ai_enrichment_enabled", True)
    monkeypatch.setattr(settings, "openai_api_key", "sk-test")
    watcher = spy()

    sain = 'def get_user(uid):\n    return db.execute("SELECT 1 FROM t WHERE id = ?", (uid,))\n'
    result = await scanner.scan(request_for(sain))
    await drain()

    assert result.findings == []
    assert watcher.calls == 0
    assert result.analysis_status == "analyzed"


# --------------------------------------------------------------------------
# Enrichissement actif
# --------------------------------------------------------------------------


@pytest.fixture
def enrichment_on(monkeypatch):
    monkeypatch.setattr(settings, "code_ai_enrichment_enabled", True)
    monkeypatch.setattr(settings, "openai_api_key", "sk-test-cle-factice")
    monkeypatch.setattr(settings, "openai_model", "gpt-4o-mini")


@pytest.mark.asyncio
async def test_la_reponse_http_n_attend_pas_le_modele(spy, enrichment_on):
    """L'editeur recoit les findings des regles immediatement."""
    spy()

    result = await scanner.scan(request_for())

    # Reponse rendue avant que le modele ait repondu.
    assert result.analysis_status == "pending"
    assert result.analysis_status_label == "En attente d'analyse"
    assert result.findings_count == 1
    assert result.findings[0].source == "rule"
    assert result.ai_enrichment_applied is False

    await drain()


@pytest.mark.asyncio
async def test_le_finding_est_enrichi_et_persiste(spy, enrichment_on):
    watcher = spy()

    result = await scanner.scan(request_for())
    await drain()

    assert watcher.calls == 1

    final = await scanner.get_scan(result.scan_uid)
    assert final is not None
    assert final.analysis_status == "analyzed"
    assert final.analysis_error is None
    assert final.ai_enrichment_applied is True
    assert final.model == "gpt-4o-mini"

    finding = final.findings[0]
    assert finding.source == "ia"
    assert finding.source_label == "Analyse IA"
    assert finding.title == VERDICT["title"]
    assert finding.why_dangerous == VERDICT["why_dangerous"]
    assert finding.potential_impact == VERDICT["potential_impact"]
    assert finding.recommendations == VERDICT["recommendations"]
    assert finding.confidence == 0.9
    # Le CWE et la categorie restent ceux de la regle.
    assert finding.cwe == "CWE-89"
    assert finding.rule_id == "SQLI001"


@pytest.mark.asyncio
async def test_le_score_est_une_fusion_pas_une_recopie(spy, enrichment_on):
    """60 % modele / 40 % deterministe, poids partages avec les alertes."""
    spy()

    result = await scanner.scan(request_for())
    deterministic = result.findings[0].risk_score
    await drain()

    final = await scanner.get_scan(result.scan_uid)
    fused = final.findings[0].risk_score

    assert fused != VERDICT["risk_score"], "le score du modele n'est pas recopie"
    assert fused != deterministic, "le score deterministe a bien ete revu"
    assert min(deterministic, VERDICT["risk_score"]) <= fused <= max(
        deterministic, VERDICT["risk_score"]
    )
    # Les facteurs cites par le modele completent l'explication.
    noms = {factor.name for factor in final.findings[0].risk_factors}
    assert "Analyse IA" in noms


@pytest.mark.asyncio
async def test_un_faux_positif_est_ecarte_sans_etre_supprime(spy, enrichment_on):
    spy(lambda request: answer({**VERDICT, "false_positive": True}))

    result = await scanner.scan(request_for())
    await drain()

    final = await scanner.get_scan(result.scan_uid)
    finding = final.findings[0]

    assert finding.status == "dismissed"
    assert finding.status_label == "Ignoré (faux positif)"
    assert finding.decision_reason
    # Toujours en base : rien n'est supprime physiquement.
    assert store.get_code_finding(finding.finding_uid) is not None
    # Et il ne compte plus dans les compteurs affiches.
    assert final.counts.total == 0


@pytest.mark.asyncio
async def test_le_secret_est_masque_avant_d_atteindre_le_modele(spy, enrichment_on):
    watcher = spy()

    await scanner.scan(request_for(SECRET_CODE))
    await drain()

    assert watcher.calls >= 1
    envoye = watcher.prompts[0]["user"]
    assert "sk-abcdefghijklmnopqrstuvwxyz0123456789" not in envoye
    assert "[REDACTED]" in envoye


@pytest.mark.asyncio
async def test_le_prompt_impose_le_francais(spy, enrichment_on):
    watcher = spy()

    await scanner.scan(request_for())
    await drain()

    systeme = watcher.prompts[0]["system"]
    assert "EXCLUSIVEMENT en français" in systeme
    assert "Ne réponds\nJAMAIS en anglais" in systeme or "JAMAIS en anglais" in systeme


# --------------------------------------------------------------------------
# Diffusion SSE
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_les_findings_enrichis_sont_pousses_en_sse(spy, enrichment_on, sse_events):
    spy()

    result = await scanner.scan(request_for())
    await drain()

    types = [event.type for event in sse_events]
    assert "code_scan" in types
    assert "code_finding" in types

    # Premier evenement : le scan passe en « analyse en cours ».
    first = sse_events[0]
    assert first.type == "code_scan"
    assert first.data["analysis_status"] == "analyzing"
    assert first.data["scan_uid"] == result.scan_uid

    finding_event = next(e for e in sse_events if e.type == "code_finding")
    assert finding_event.data["source"] == "ia"
    assert finding_event.data["file_path"] == "src/api/users.py"
    assert finding_event.data["scan_uid"] == result.scan_uid
    assert finding_event.data["severity_label"]

    last = sse_events[-1]
    assert last.type == "code_scan"
    assert last.data["analysis_status"] == "analyzed"


@pytest.mark.asyncio
async def test_une_panne_sse_n_invalide_pas_l_enrichissement(
    spy, enrichment_on, monkeypatch
):
    spy()

    async def broken(event, event_id=None):
        raise RuntimeError("diffuseur indisponible")

    monkeypatch.setattr(stream, "publish", broken)

    result = await scanner.scan(request_for())
    await drain()

    final = await scanner.get_scan(result.scan_uid)
    assert final.analysis_status == "analyzed"
    assert final.findings[0].source == "ia"


# --------------------------------------------------------------------------
# Echecs
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_une_panne_du_modele_marque_le_scan_en_echec(spy, enrichment_on):
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("service injoignable")

    spy(down)

    result = await scanner.scan(request_for())
    await drain()

    final = await scanner.get_scan(result.scan_uid)
    assert final.analysis_status == "failed"
    assert final.analysis_status_label == "Échec de l'analyse"
    assert final.analysis_error
    assert final.ai_enrichment_applied is False
    assert final.model == ""
    # Le finding deterministe reste intact : rien n'est invente.
    assert final.findings[0].source == "rule"
    assert final.findings[0].title == "Requête SQL construite par concaténation"


@pytest.mark.asyncio
async def test_une_reponse_invalide_du_modele_est_un_echec(spy, enrichment_on):
    spy(lambda request: httpx.Response(200, json={"choices": [{"message": {}}]}))

    result = await scanner.scan(request_for())
    await drain()

    final = await scanner.get_scan(result.scan_uid)
    assert final.analysis_status == "failed"
    assert final.findings[0].source == "rule"


@pytest.mark.asyncio
async def test_un_quota_depasse_est_signale_en_francais(spy, enrichment_on):
    spy(lambda request: httpx.Response(429, json={"error": {"message": "rate limit"}}))

    result = await scanner.scan(request_for())
    await drain()

    final = await scanner.get_scan(result.scan_uid)
    assert final.analysis_status == "failed"
    assert "Quota" in final.analysis_error


@pytest.mark.asyncio
async def test_un_echec_partiel_reste_une_analyse_aboutie(spy, enrichment_on):
    """Deux findings, un seul enrichi : le scan aboutit et le dit."""
    calls = {"n": 0}

    def flaky(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return answer(VERDICT)
        return httpx.Response(500, json={"error": {"message": "boom"}})

    spy(flaky)

    code = VULNERABLE + "requests.get(url, verify=False)\n"
    result = await scanner.scan(request_for(code))
    await drain()

    final = await scanner.get_scan(result.scan_uid)
    assert final.analysis_status == "analyzed"
    assert final.analysis_error and "non enrichi" in final.analysis_error
    sources = {finding.source for finding in final.findings}
    assert sources == {"ia", "rule"}


@pytest.mark.asyncio
async def test_l_enrichissement_ne_leve_jamais_vers_l_appelant(spy, enrichment_on):
    """Une erreur inattendue ne doit pas casser la reponse HTTP."""

    def boom(request: httpx.Request) -> httpx.Response:
        raise ValueError("panne interne du transport")

    spy(boom)

    # Le scan lui-meme aboutit toujours.
    result = await scanner.scan(request_for())
    assert result.findings_count == 1
    await drain()

    final = await scanner.get_scan(result.scan_uid)
    assert final.analysis_status == "failed"


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_un_contenu_deja_enrichi_ne_rappelle_pas_le_modele(spy, enrichment_on):
    watcher = spy()

    await scanner.scan(request_for())
    await drain()
    assert watcher.calls == 1

    again = await scanner.scan(request_for())
    await drain()

    assert watcher.calls == 1, "le cache evite un second appel au modele"
    assert again.cached is True
    assert again.analysis_status == "analyzed"
    assert again.ai_enrichment_applied is True
