"""Tests des endpoints /api/code/*.

Base SQLite temporaire, aucun reseau, aucun OpenAI, aucun Wazuh requis.
Verifie aussi que le routeur de code ne perturbe pas les routes
existantes.
"""

import pytest
from fastapi.testclient import TestClient

from app.code.schemas import content_hash_of
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


# --------------------------------------------------------------------------
# Etat du service
# --------------------------------------------------------------------------


def test_health_expose_l_etat_du_service(client):
    body = client.get("/api/code/health").json()

    assert body["status"] == "ok"
    assert body["analysis_enabled"] is True
    # Phase 1 : aucune capacite IA n'est annoncee.
    assert body["ai_enabled"] is False
    assert body["rules_version"]
    assert body["rules_count"] > 0
    assert body["api_version"]
    assert body["max_content_bytes"] > 0


def test_le_catalogue_des_regles_est_expose(client):
    body = client.get("/api/code/rules").json()

    assert len(body) >= 8
    rule = next(item for item in body if item["rule_id"] == "SQLI001")
    assert rule["category"] == "sql_injection"
    assert rule["category_label"] == "SQL injection"
    assert rule["cwe"] == "CWE-89"
    assert rule["owasp"].startswith("A03:2021")
    assert rule["severity"] == "CRITICAL"
    assert rule["severity_label"] == "CRITIQUE"
    assert rule["description"]


# --------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------


def test_un_scan_retourne_les_findings(client):
    body = scan(client, VULNERABLE)

    assert body["analysis_status"] == "analyzed"
    assert body["analysis_status_label"] == "Analysée"
    assert body["cached"] is False
    assert body["findings_count"] == 1

    finding = body["findings"][0]
    assert finding["category"] == "sql_injection"
    assert finding["severity"] == "CRITICAL"
    assert finding["location"]["line_start"] == 2
    assert finding["why_dangerous"]
    assert finding["potential_impact"]
    assert finding["recommendations"]
    assert finding["risk_factors"]


def test_un_contenu_vide_est_refuse(client):
    response = client.post(
        "/api/code/scan",
        json={"file_path": "a.py", "language": "python", "content": "   "},
    )

    assert response.status_code == 422
    assert "vide" in response.text


def test_un_hash_incorrect_est_refuse(client):
    body = payload(VULNERABLE)
    body["content_hash"] = "0" * 64

    response = client.post("/api/code/scan", json=body)

    assert response.status_code == 422
    assert "empreinte" in response.text.lower()


def test_un_contenu_trop_volumineux_est_refuse(client, monkeypatch):
    monkeypatch.setattr(settings, "code_max_content_bytes", 50)

    response = client.post("/api/code/scan", json=payload(VULNERABLE))

    assert response.status_code == 422
    assert "volumineux" in response.text


def test_le_cache_evite_un_second_scan(client):
    first = scan(client, VULNERABLE)
    second = scan(client, VULNERABLE)

    assert first["cached"] is False
    assert second["cached"] is True
    assert second["scan_uid"] == first["scan_uid"]
    assert client.get("/api/code/stats").json()["scans"] == 1


def test_un_scan_est_relisible(client):
    created = scan(client, VULNERABLE)

    body = client.get(f"/api/code/scans/{created['scan_uid']}").json()

    assert body["scan_uid"] == created["scan_uid"]
    assert body["findings_count"] == created["findings_count"]


def test_un_scan_inconnu_repond_404_en_francais(client):
    response = client.get("/api/code/scans/inexistant")

    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "Analyse introuvable"


def test_l_analyse_desactivee_repond_503(client, monkeypatch):
    monkeypatch.setattr(settings, "code_analysis_enabled", False)

    response = client.post("/api/code/scan", json=payload(VULNERABLE))

    assert response.status_code == 503
    assert "désactivée" in response.json()["detail"]["error"]


# --------------------------------------------------------------------------
# Findings et filtres
# --------------------------------------------------------------------------


def test_les_findings_sont_listes_et_filtrables(client):
    scan(client, VULNERABLE, file_path="src/api/users.py")
    scan(client, CONFIG_RISQUEE, file_path="src/config/http.py")

    tous = client.get("/api/code/findings").json()
    assert len(tous) == 2

    par_fichier = client.get(
        "/api/code/findings?file_path=src/api/users.py"
    ).json()
    assert len(par_fichier) == 1
    assert par_fichier[0]["category"] == "sql_injection"

    critiques = client.get("/api/code/findings?severity=CRITICAL").json()
    assert all(item["severity"] == "CRITICAL" for item in critiques)

    ouverts = client.get("/api/code/findings?status=open").json()
    assert len(ouverts) == 2

    categorie = client.get(
        "/api/code/findings?category=insecure_configuration"
    ).json()
    assert len(categorie) == 1

    futur = client.get("/api/code/findings?since=2099-01-01T00:00:00").json()
    assert futur == []


def test_les_findings_sont_pagines(client):
    scan(client, VULNERABLE + CONFIG_RISQUEE)

    page = client.get("/api/code/findings?limit=1&offset=0").json()
    suivante = client.get("/api/code/findings?limit=1&offset=1").json()

    assert len(page) == 1
    assert len(suivante) == 1
    assert page[0]["finding_uid"] != suivante[0]["finding_uid"]


# --------------------------------------------------------------------------
# Decisions
# --------------------------------------------------------------------------


def test_un_finding_peut_etre_ignore(client):
    body = scan(client, VULNERABLE)
    uid = body["findings"][0]["finding_uid"]

    response = client.post(
        f"/api/code/findings/{uid}/decision",
        json={"status": "dismissed", "reason": "Requête interne, id validé en amont"},
    )

    assert response.status_code == 200
    updated = response.json()
    assert updated["status"] == "dismissed"
    assert updated["status_label"] == "Ignoré (faux positif)"
    assert updated["decision_reason"]

    # Jamais supprime physiquement : il reste consultable.
    assert client.get(f"/api/code/findings?status=dismissed").json()


def test_un_finding_peut_etre_marque_corrige(client):
    body = scan(client, VULNERABLE)
    uid = body["findings"][0]["finding_uid"]

    updated = client.post(
        f"/api/code/findings/{uid}/decision", json={"status": "fixed"}
    ).json()

    assert updated["status"] == "fixed"
    assert updated["status_label"] == "Corrigé"
    assert client.get("/api/code/stats").json()["fixed"] == 1


def test_une_decision_invalide_est_refusee(client):
    body = scan(client, VULNERABLE)
    uid = body["findings"][0]["finding_uid"]

    response = client.post(
        f"/api/code/findings/{uid}/decision", json={"status": "supprime"}
    )

    assert response.status_code == 422


def test_une_decision_sur_un_finding_inconnu_repond_404(client):
    response = client.post(
        "/api/code/findings/inconnu/decision", json={"status": "fixed"}
    )

    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "Finding introuvable"


# --------------------------------------------------------------------------
# Proposition de correctif
# --------------------------------------------------------------------------


def test_un_correctif_mecanique_est_propose(client):
    body = scan(client, CONFIG_RISQUEE)
    uid = body["findings"][0]["finding_uid"]

    proposal = client.post(f"/api/code/findings/{uid}/fix").json()

    assert proposal["available"] is True
    assert "verify=False" in proposal["original_line"]
    assert "verify=True" in proposal["replacement_line"]
    assert proposal["diff"]
    assert proposal["explanation"]
    # Rappel explicite : rien n'est applique par le backend.
    assert proposal["applies_automatically"] is False


def test_aucun_correctif_automatique_pour_une_sql_injection(client):
    body = scan(client, VULNERABLE)
    uid = body["findings"][0]["finding_uid"]

    proposal = client.post(f"/api/code/findings/{uid}/fix").json()

    assert proposal["available"] is False
    assert proposal["blockers"]
    assert "paramétrée" in proposal["blockers"][0]
    # Les etapes manuelles reprennent les recommandations de la regle.
    assert proposal["manual_steps"]


def test_un_correctif_est_refuse_si_la_ligne_a_change(client):
    body = scan(client, CONFIG_RISQUEE)
    uid = body["findings"][0]["finding_uid"]

    proposal = client.post(
        f"/api/code/findings/{uid}/fix",
        params={"current_line": "response = requests.get(url, timeout=5)"},
    ).json()

    assert proposal["available"] is False
    assert "changé" in proposal["blockers"][0]


def test_un_correctif_sur_un_finding_inconnu_repond_404(client):
    response = client.post("/api/code/findings/inconnu/fix")

    assert response.status_code == 404


def test_aucun_correctif_sur_un_finding_deja_traite(client):
    body = scan(client, CONFIG_RISQUEE)
    uid = body["findings"][0]["finding_uid"]
    client.post(f"/api/code/findings/{uid}/decision", json={"status": "dismissed"})

    proposal = client.post(f"/api/code/findings/{uid}/fix").json()

    assert proposal["available"] is False


# --------------------------------------------------------------------------
# Statistiques
# --------------------------------------------------------------------------


def test_les_statistiques_refletent_les_scans(client):
    scan(client, VULNERABLE, file_path="src/api/users.py")
    scan(client, CONFIG_RISQUEE, file_path="src/config/http.py")

    body = client.get("/api/code/stats").json()

    assert body["scans"] == 2
    assert body["files"] == 2
    assert body["findings"] == 2
    assert body["open"] == 2
    assert body["dismissed"] == 0
    assert body["fixed"] == 0
    assert body["by_severity"]["critical"] >= 1
    assert "sql_injection" in body["by_category"]
    assert body["ai_enabled"] is False
    assert body["rules_version"]


# --------------------------------------------------------------------------
# Non-regression sur l'existant
# --------------------------------------------------------------------------


def test_les_routes_existantes_repondent_toujours(client):
    """Le routeur de code n'altere aucune route Wazuh ou IA."""
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/config").status_code == 200
    assert client.get("/api/ai/stats").status_code == 200
    assert client.get("/api/ai/notifications").status_code == 200
    assert client.get("/api/monitoring/status").status_code == 200
