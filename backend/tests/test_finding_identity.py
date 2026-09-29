"""Identite des findings entre projets (correctif de la phase 2).

Le defaut corrige : l'identifiant d'un finding etait tire de sa seule
empreinte, qui ne porte pas le projet, alors que la colonne `finding_id`
est unique dans toute la base. Deux projets portant le meme secret au meme
endroit — un `backend/config.py` commun a deux clones, par exemple —
produisaient le meme identifiant, et le second balayage echouait sur la
contrainte d'unicite.

Ce que ces tests verrouillent :

    COEXISTENCE     le meme constat existe dans deux projets, pour les
                    trois familles (secret, API, dependance).
    CLOISONNEMENT   chaque projet ne voit que le sien, et decider d'un
                    finding dans un projet ne touche pas l'autre.
    STABILITE       dans un projet, deux balayages identiques donnent le
                    meme identifiant, et une decision de l'utilisateur
                    survit au balayage suivant — comme avant.
    COMPATIBILITE   une ligne ecrite avant le correctif garde son
                    identifiant : l'extension ne perd rien de ce qu'elle
                    connait.
"""

import json

import pytest
from fastapi.testclient import TestClient

from app import store
from app.main import app
from app.security.dependencies import record_inventory
from app.security.schemas import finding_id_for
from app.security.secrets import fingerprint_of
from app.security.schemas import SecretFindingSubmission
from tests.conftest import auth_headers
from tests.test_security_dependencies import AVIS, FakeProvider, inventory, record


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def register(client: TestClient, name: str) -> str:
    response = client.post(
        "/api/project/discover",
        json={"root_hash": f"{abs(hash(name)):064x}"[:64], "project_name": name},
        headers=auth_headers(),
    )
    assert response.status_code == 200, response.text
    return response.json()["project_uid"]


SECRET = {
    "rule_id": "secret.openai_api_key",
    "file_path": "backend/config.py",
    "line": 24,
    "column": 12,
    "secret_type": "openai_api_key",
    "severity": "CRITICAL",
    "confidence": "HIGH",
    "evidence_redacted": "OpenAI API key detected: sk-proj-********",
    "title": "",
    "description": "",
    "remediation": "",
    "references": [],
}

API = {
    "rule_id": "API-AUTH-001",
    "file_path": "src/api.py",
    "line": 12,
    "issue_type": "unauthenticated_endpoint",
    "endpoint": "/admin",
    "http_method": "POST",
    "framework": "fastapi",
    "severity": "HIGH",
    "confidence": "MEDIUM",
    "evidence": '@app.post("/admin")',
    "title": "Endpoint sans authentification apparente",
    "description": "",
    "remediation": "",
    "references": [],
}


def scan_secrets(client: TestClient, uid: str, findings: list[dict]):
    return client.post(
        f"/api/project/{uid}/secrets",
        json={"findings": findings, "scanned_files": 1, "engine": "secret-scanner"},
        headers=auth_headers(),
    )


def scan_api(client: TestClient, uid: str, findings: list[dict]):
    return client.post(
        f"/api/project/{uid}/api-security",
        json={"findings": findings, "scanned_files": 1, "endpoints_detected": 1},
        headers=auth_headers(),
    )


# --------------------------------------------------------------------------
# Coexistence
# --------------------------------------------------------------------------


def test_le_meme_secret_existe_dans_deux_projets(client):
    premier = register(client, "clone-a")
    second = register(client, "clone-b")

    assert scan_secrets(client, premier, [SECRET]).status_code == 200
    # Avant le correctif : erreur d'unicite ici.
    response = scan_secrets(client, second, [SECRET])
    assert response.status_code == 200, response.text

    a = store.list_security_findings(premier)
    b = store.list_security_findings(second)
    assert len(a) == len(b) == 1
    assert a[0]["finding_id"] != b[0]["finding_id"]
    # Meme constat, meme empreinte : c'est l'identifiant qui differe.
    assert a[0]["fingerprint"] == b[0]["fingerprint"]


def test_le_meme_probleme_d_api_existe_dans_deux_projets(client):
    premier = register(client, "api-a")
    second = register(client, "api-b")

    assert scan_api(client, premier, [API]).status_code == 200
    assert scan_api(client, second, [API]).status_code == 200

    assert len(store.list_security_findings(premier)) == 1
    assert len(store.list_security_findings(second)) == 1


@pytest.mark.asyncio
async def test_la_meme_dependance_vulnerable_existe_dans_deux_projets(client):
    premier = register(client, "deps-a")
    second = register(client, "deps-b")
    vulnerable = record("express", "4.17.1")

    resultats = []
    for uid in (premier, second):
        project_id = int(store.get_project_by_uid(uid)["id"])
        provider = FakeProvider(vulnerabilities={vulnerable.key: [AVIS]})
        resultats.append(
            await record_inventory(uid, project_id, inventory(vulnerable), provider)
        )

    (a,), (b,) = (r.findings for r in resultats)
    assert a.id != b.id
    assert a.project_uid == premier
    assert b.project_uid == second


# --------------------------------------------------------------------------
# Cloisonnement
# --------------------------------------------------------------------------


def test_chaque_projet_ne_voit_que_son_finding(client):
    premier = register(client, "vue-a")
    second = register(client, "vue-b")
    scan_secrets(client, premier, [SECRET])
    scan_secrets(client, second, [SECRET])

    for uid in (premier, second):
        body = client.get(
            f"/api/project/{uid}/findings", headers=auth_headers()
        ).json()
        assert len(body) == 1
        assert body[0]["project_uid"] == uid


def test_ecarter_un_finding_dans_un_projet_ne_touche_pas_l_autre(client):
    premier = register(client, "decision-a")
    second = register(client, "decision-b")
    scan_secrets(client, premier, [SECRET])
    scan_secrets(client, second, [SECRET])

    cible = store.list_security_findings(premier)[0]["finding_id"]
    with store.get_connection() as connection:
        connection.execute(
            "UPDATE security_findings SET status = 'dismissed' WHERE finding_id = ?",
            (cible,),
        )

    assert store.list_security_findings(premier)[0]["status"] == "dismissed"
    assert store.list_security_findings(second)[0]["status"] == "open"


def test_un_nouveau_balayage_d_un_projet_ne_supprime_pas_celui_de_l_autre(client):
    premier = register(client, "sync-a")
    second = register(client, "sync-b")
    scan_secrets(client, premier, [SECRET])
    scan_secrets(client, second, [SECRET])

    # Le premier projet corrige son secret : son balayage revient vide.
    scan_secrets(client, premier, [])

    assert store.list_security_findings(premier) == []
    assert len(store.list_security_findings(second)) == 1


# --------------------------------------------------------------------------
# Stabilite dans un projet
# --------------------------------------------------------------------------


def test_deux_balayages_identiques_donnent_le_meme_identifiant(client):
    uid = register(client, "stable")
    premier = scan_secrets(client, uid, [SECRET]).json()["findings"][0]["id"]
    second = scan_secrets(client, uid, [SECRET]).json()["findings"][0]["id"]

    assert premier == second


def test_une_decision_survit_au_balayage_suivant(client):
    uid = register(client, "decision-durable")
    scan_secrets(client, uid, [SECRET])
    cible = store.list_security_findings(uid)[0]["finding_id"]
    with store.get_connection() as connection:
        connection.execute(
            "UPDATE security_findings SET status = 'dismissed' WHERE finding_id = ?",
            (cible,),
        )

    scan_secrets(client, uid, [SECRET])

    row = store.get_security_finding(cible)
    assert row is not None
    assert row["status"] == "dismissed"


def test_l_identifiant_depend_du_projet_et_de_l_empreinte():
    assert finding_id_for("a", "f") != finding_id_for("b", "f")
    assert finding_id_for("a", "f") != finding_id_for("a", "g")
    assert finding_id_for("a", "f") == finding_id_for("a", "f")
    assert len(finding_id_for("a", "f")) == 32


# --------------------------------------------------------------------------
# Compatibilite avec une base existante
# --------------------------------------------------------------------------


def test_une_ligne_ecrite_avant_le_correctif_garde_son_identifiant(client):
    """L'ancien identifiant (`empreinte[:32]`) n'est jamais reecrit.

    La reconciliation retrouve la ligne par son empreinte et met a jour son
    contenu, pas son identifiant : ce que l'extension connait reste valable.
    """
    uid = register(client, "base-ancienne")
    submission = SecretFindingSubmission(**SECRET)
    fingerprint = fingerprint_of(submission)
    ancien = fingerprint[:32]

    store.sync_security_findings(
        uid,
        "SECRET",
        [
            {
                "finding_id": ancien,
                "fingerprint": fingerprint,
                "severity": "CRITICAL",
                "confidence": "HIGH",
                "title": "Ancien titre",
                "file_path": "backend/config.py",
                "line_start": 24,
                "line_end": 24,
                "evidence": "sk-proj-********",
                "reference_links": json.dumps([]),
                "detection_engine": "secret-scanner",
            }
        ],
    )

    body = scan_secrets(client, uid, [SECRET]).json()

    assert [item["id"] for item in body["findings"]] == [ancien]
    # Et un autre projet peut desormais porter le meme constat.
    autre = register(client, "base-nouvelle")
    assert scan_secrets(client, autre, [SECRET]).status_code == 200
