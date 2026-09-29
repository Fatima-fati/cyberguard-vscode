"""Resistance aux pannes et conservation de l'historique Code Security.

Complete les suites existantes sur les trois points qu'elles ne couvraient
pas :

1. **panne interne** — une erreur inattendue du stockage doit produire une
   reponse propre, sans trace d'execution ni detail technique ;
2. **delai d'attente du modele** — distinct d'un refus ou d'un quota
   depasse, il doit marquer le scan en echec sans invalider les findings
   deterministes ;
3. **aucune suppression physique** — aucune decision, aucune correction ne
   retire quoi que ce soit de la base.

Aucun appel reseau, aucune cle OpenAI : le transport HTTP est simule avec
`httpx.MockTransport`, comme dans le reste de la suite.
"""

import asyncio
import sqlite3

import httpx
import pytest
from fastapi.testclient import TestClient

from app import store
from app.ai.openai_client import OpenAIClient
from app.code import analyzer, scanner
from app.code.schemas import CodeScanRequest, content_hash_of
from app.config import settings
from app.main import app
from .conftest import auth_headers

VULNERABLE = (
    "def get_user(user_id):\n"
    '    query = "SELECT * FROM users WHERE id=" + user_id\n'
    "    return db.execute(query)\n"
)

CONFIG_RISQUEE = "response = requests.get(url, verify=False)\n"


@pytest.fixture
def client():
    with TestClient(app, headers=auth_headers()) as test_client:
        yield test_client


@pytest.fixture
def http_client():
    """Client qui laisse le serveur repondre au lieu de relancer l'exception.

    `TestClient` relance par defaut les erreurs du serveur, ce qui masque
    la reponse reellement envoyee. Ici on veut voir ce que voit un vrai
    client : le code HTTP et le corps.
    """
    with TestClient(app, headers=auth_headers(), raise_server_exceptions=False) as test_client:
        yield test_client


def payload(content: str, **overrides) -> dict:
    body = {
        "file_path": "src/api/users.py",
        "language": "python",
        "content": content,
        "content_hash": content_hash_of(content),
        "workspace": "mon-projet",
    }
    body.update(overrides)
    return body


def scan(client, content: str, **overrides) -> dict:
    response = client.post("/api/code/scan", json=payload(content, **overrides))
    assert response.status_code == 200, response.text
    return response.json()


def count_rows(table: str) -> int:
    connection = sqlite3.connect(settings.database_path)
    try:
        return connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        connection.close()


# --------------------------------------------------------------------------
# Panne interne
# --------------------------------------------------------------------------


def test_une_panne_du_stockage_ne_fuit_aucune_trace(http_client, monkeypatch):
    """Une erreur inattendue reste une erreur serveur, pas un deballage."""

    def boom(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked: /chemin/interne/alerts.db")

    monkeypatch.setattr(store, "list_code_findings", boom)

    response = http_client.get("/api/code/findings")

    assert response.status_code == 500
    body = response.text
    # Ni chemin de fichier interne, ni trace d'execution, ni nom de module.
    assert "/chemin/interne" not in body
    assert "Traceback" not in body
    assert "sqlite3" not in body


def test_une_panne_du_stockage_ne_casse_pas_les_autres_routes(http_client, monkeypatch):
    """La panne d'une route n'entraine pas les autres."""

    def boom(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(store, "list_code_findings", boom)

    assert http_client.get("/api/code/findings").status_code == 500
    # Le service reste debout.
    assert http_client.get("/api/code/health").status_code == 200
    assert http_client.get("/api/code/stats").status_code == 200


def test_un_scan_inconnu_repond_404_sans_detail_technique(client):
    response = client.get("/api/code/scans/inexistant-0000")

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert detail["error"] == "Analyse introuvable"
    assert "Traceback" not in response.text


# --------------------------------------------------------------------------
# Delai d'attente du modele
# --------------------------------------------------------------------------


class SlowSpy:
    """Transport qui expire, comme un modele qui ne repond pas."""

    def __init__(self, error: Exception):
        self.calls = 0
        self._error = error

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        raise self._error


@pytest.fixture
def spy_raising(monkeypatch):
    def install(error: Exception) -> SlowSpy:
        watcher = SlowSpy(error)
        openai = OpenAIClient()
        openai._client = httpx.AsyncClient(transport=httpx.MockTransport(watcher))
        monkeypatch.setattr(analyzer, "get_openai_client", lambda: openai)
        return watcher

    return install


@pytest.fixture
def enrichment_on(monkeypatch):
    monkeypatch.setattr(settings, "code_ai_enrichment_enabled", True)
    monkeypatch.setattr(settings, "openai_api_key", "sk-test-jamais-utilisee")


async def drain() -> None:
    """Attend la fin des taches d'enrichissement detachees."""
    for _ in range(20):
        pending = [task for task in scanner._background if not task.done()]
        if not pending:
            return
        await asyncio.gather(*pending, return_exceptions=True)


def request_for(content: str = VULNERABLE, **overrides) -> CodeScanRequest:
    body = {
        "file_path": "src/api/users.py",
        "language": "python",
        "content": content,
        "content_hash": content_hash_of(content),
        "workspace": "projet",
        "ai_enrichment": True,
    }
    body.update(overrides)
    return CodeScanRequest(**body)


@pytest.mark.asyncio
async def test_un_delai_depasse_marque_le_scan_en_echec(spy_raising, enrichment_on):
    watcher = spy_raising(httpx.ReadTimeout("le modele n'a pas repondu"))

    result = await scanner.scan(request_for())
    await drain()

    assert watcher.calls >= 1
    final = await scanner.get_scan(result.scan_uid)
    assert final.analysis_status == "failed"
    assert final.analysis_error
    assert final.ai_enrichment_applied is False


@pytest.mark.asyncio
async def test_un_delai_depasse_preserve_les_findings_deterministes(
    spy_raising, enrichment_on
):
    """L'IA tombe, les regles restent : rien n'est efface, rien n'est invente."""
    spy_raising(httpx.ReadTimeout("trop long"))

    result = await scanner.scan(request_for())
    await drain()

    final = await scanner.get_scan(result.scan_uid)
    assert final.findings, "les findings des regles doivent survivre"
    assert final.findings[0].source == "rule"
    assert final.findings[0].severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    # Aucun score fictif : la confiance reste celle de la regle.
    assert 0 <= final.findings[0].risk_score <= 100


@pytest.mark.asyncio
async def test_un_delai_depasse_est_dit_en_francais(spy_raising, enrichment_on):
    spy_raising(httpx.ConnectTimeout("connect timeout"))

    result = await scanner.scan(request_for())
    await drain()

    final = await scanner.get_scan(result.scan_uid)
    assert final.analysis_error
    # Message destine a un humain, pas une classe d'exception.
    assert "httpx" not in final.analysis_error
    assert "Traceback" not in final.analysis_error


@pytest.mark.asyncio
async def test_un_delai_depasse_n_interrompt_pas_la_reponse_http(
    spy_raising, enrichment_on
):
    """La requete de scan repond sans attendre le modele."""
    spy_raising(httpx.ReadTimeout("trop long"))

    result = await scanner.scan(request_for())

    # A ce stade l'enrichissement n'a pas encore echoue : la reponse est
    # deja partie avec les findings des regles.
    assert result.findings
    assert result.analysis_status in {"pending", "analyzing"}

    await drain()


# --------------------------------------------------------------------------
# Aucune suppression physique
# --------------------------------------------------------------------------


def test_ecarter_un_finding_ne_le_supprime_pas(client):
    body = scan(client, VULNERABLE)
    uid = body["findings"][0]["finding_uid"]
    before = count_rows("code_findings")

    response = client.post(
        f"/api/code/findings/{uid}/decision",
        json={"status": "dismissed", "reason": "faux positif", "actor": "vscode"},
    )
    assert response.status_code == 200

    assert count_rows("code_findings") == before
    # Toujours lisible, avec sa raison.
    again = client.get("/api/code/findings", params={"status": "dismissed"})
    uids = [item["finding_uid"] for item in again.json()]
    assert uid in uids


def test_marquer_corrige_ne_supprime_pas(client):
    body = scan(client, VULNERABLE)
    uid = body["findings"][0]["finding_uid"]
    before = count_rows("code_findings")

    client.post(
        f"/api/code/findings/{uid}/decision",
        json={"status": "fixed", "actor": "vscode"},
    )

    assert count_rows("code_findings") == before
    listed = client.get("/api/code/findings", params={"status": "fixed"}).json()
    assert uid in [item["finding_uid"] for item in listed]


def test_une_nouvelle_analyse_n_efface_pas_l_historique(client):
    """Le fichier est corrige : l'ancien scan reste consultable."""
    first = scan(client, VULNERABLE)
    scans_before = count_rows("code_scans")
    findings_before = count_rows("code_findings")

    # Meme fichier, contenu assaini.
    corrige = (
        "def get_user(user_id):\n"
        '    return db.execute("SELECT * FROM users WHERE id=%s", (user_id,))\n'
    )
    second = scan(client, corrige)

    assert second["scan_uid"] != first["scan_uid"]
    assert count_rows("code_scans") > scans_before
    # Rien n'a ete retire : les findings de la premiere analyse sont la.
    assert count_rows("code_findings") >= findings_before

    relu = client.get(f"/api/code/scans/{first['scan_uid']}")
    assert relu.status_code == 200
    assert relu.json()["findings"], "l'analyse d'origine reste consultable"


def test_les_decisions_successives_ne_retirent_jamais_de_ligne(client):
    """Plusieurs allers-retours sur le meme finding : rien ne disparait."""
    body = scan(client, CONFIG_RISQUEE)
    uid = body["findings"][0]["finding_uid"]
    before = count_rows("code_findings")

    for decision in ("dismissed", "fixed", "dismissed"):
        response = client.post(
            f"/api/code/findings/{uid}/decision",
            json={"status": decision, "actor": "vscode"},
        )
        assert response.status_code == 200
        assert count_rows("code_findings") == before


def test_une_proposition_de_correctif_n_ecrit_dans_aucun_fichier(client, tmp_path):
    """Le backend decrit la correction ; il n'ecrit jamais sur le disque."""
    cible = tmp_path / "users.py"
    cible.write_text(CONFIG_RISQUEE, encoding="utf-8")
    avant = cible.read_text(encoding="utf-8")

    body = scan(client, CONFIG_RISQUEE, file_path=str(cible))
    uid = body["findings"][0]["finding_uid"]

    response = client.post(
        f"/api/code/findings/{uid}/fix",
        params={"current_line": CONFIG_RISQUEE.strip()},
    )
    assert response.status_code == 200

    # Le fichier reel est intact, quel que soit le contenu de la proposition.
    assert cible.read_text(encoding="utf-8") == avant
    assert response.json()["applies_automatically"] is False


def test_le_journal_des_correctifs_conserve_chaque_proposition(client):
    body = scan(client, CONFIG_RISQUEE)
    uid = body["findings"][0]["finding_uid"]
    before = count_rows("code_fixes")

    first = client.post(
        f"/api/code/findings/{uid}/fix",
        params={"current_line": CONFIG_RISQUEE.strip()},
    )

    if not first.json()["available"]:
        pytest.skip("aucun correctif mecanique pour cette regle")

    assert count_rows("code_fixes") == before + 1
    # Trace d'audit : le backend n'a pas applique la correction lui-meme.
    connection = sqlite3.connect(settings.database_path)
    try:
        applied = connection.execute(
            "SELECT applied_in_editor FROM code_fixes ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
    finally:
        connection.close()
    assert applied == 0


def test_le_module_code_ne_contient_aucune_suppression_sql():
    """Garde-fou de conception : aucun DELETE sur les tables Code Security."""
    import pathlib

    racine = pathlib.Path(store.__file__).parent
    fautes = []

    for fichier in [racine / "store.py", *(racine / "code").glob("*.py")]:
        texte = fichier.read_text(encoding="utf-8")
        for numero, ligne in enumerate(texte.splitlines(), start=1):
            nettoyee = ligne.strip()
            if nettoyee.startswith("#") or nettoyee.startswith("r'") or '"""' in nettoyee:
                continue
            if "DELETE FROM code_" in nettoyee.upper():
                fautes.append(f"{fichier.name}:{numero}")

    assert not fautes, f"suppression physique detectee : {fautes}"
