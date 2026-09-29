"""Tests de la route de securite d'API (phase 5).

Ce que ces tests verrouillent, et pourquoi chacun compte :

    EXPURGATION    le backend n'accorde aucune confiance au client. Une
                   ligne de configuration d'API est precisement l'endroit
                   ou un jeton se glisse, et le validateur la reexpurge.
    CONFIANCE      une detection moyennement sure ne s'affiche jamais en
                   CRITICAL. Une liste de findings critiques dont un sur
                   deux est faux cesse d'etre lue.
    RECONCILIATION un second passage conserve ce que l'utilisateur a
                   ecarte et supprime ce qui a disparu.
    CLOISONNEMENT  deux projets analyses par le meme backend ne melangent
                   jamais leurs findings.
    SANS WAZUH     la route repond a l'identique avec Wazuh arrete.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.security import api_security
from app.security.schemas import ApiFindingSubmission, ApiScanSubmission
from tests.conftest import auth_headers


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def unauthenticated_client():
    with TestClient(app) as test_client:
        yield test_client


# --------------------------------------------------------------------------
# Fabriques
# --------------------------------------------------------------------------


def finding(**overrides) -> dict:
    """Un constat d'API, dans la forme que l'extension envoie."""
    payload = {
        "rule_id": "API-AUTH-001",
        "file_path": "src/api.py",
        "line": 12,
        "issue_type": "unauthenticated_endpoint",
        "endpoint": "/admin/purge",
        "http_method": "POST",
        "framework": "fastapi",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "evidence": '@app.post("/admin/purge")',
        "title": "Endpoint sans authentification apparente",
        "description": "Aucune marque d'authentification trouvee.",
        "remediation": "Ajoutez une dependance d'authentification.",
        "references": ["CWE-306"],
    }
    payload.update(overrides)
    return payload


def submission(**overrides) -> dict:
    payload = {
        "findings": [finding()],
        "scanned_files": 3,
        "endpoints_detected": 5,
        "engine": "api-scanner",
        "engine_version": "1.0.0",
        "truncated": False,
        "warnings": [],
    }
    payload.update(overrides)
    return payload


def register(client, name="projet-api") -> str:
    """Enregistre un projet et retourne son identifiant."""
    response = client.post(
        "/api/project/discover",
        json={
            "root_hash": f"{abs(hash(name)):064x}"[:64],
            "project_name": name,
            "discovery_version": "1.0.0",
        },
        headers=auth_headers(),
    )
    assert response.status_code == 200, response.text
    return response.json()["project_uid"]


# --------------------------------------------------------------------------
# Route
# --------------------------------------------------------------------------


def test_soumission_enregistree_et_comptee(client):
    project_uid = register(client)

    response = client.post(
        f"/api/project/{project_uid}/api-security",
        json=submission(),
        headers=auth_headers(),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["project_uid"] == project_uid
    assert len(body["findings"]) == 1
    assert body["statistics"]["total"] == 1
    # Le decompte de routes dit la couverture, pas le risque.
    assert body["statistics"]["endpoints_detected"] == 5
    assert body["statistics"]["scanned_files"] == 3
    assert body["statistics"]["unauthenticated_endpoints"] == 1
    assert body["statistics"]["last_scan"] is not None


def test_finding_porte_une_preuve_utile(client):
    project_uid = register(client, "projet-preuve")

    body = client.post(
        f"/api/project/{project_uid}/api-security",
        json=submission(),
        headers=auth_headers(),
    ).json()

    found = body["findings"][0]
    assert found["file"] == "src/api.py"
    assert found["line_start"] == 12
    assert found["category"] == "API"
    assert found["detection_engine"] == "api-scanner"
    assert found["title"]
    assert found["remediation"]
    assert "CWE-306" in found["references"]


def test_projet_inconnu_repond_404(client):
    response = client.post(
        "/api/project/inexistant/api-security",
        json=submission(),
        headers=auth_headers(),
    )
    assert response.status_code == 404


def test_route_refuse_un_appel_anonyme(unauthenticated_client):
    response = unauthenticated_client.post(
        "/api/project/x/api-security", json=submission()
    )
    assert response.status_code in (401, 403)


def test_capacite_desactivee_repond_503(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "api_security_enabled", False)
    project_uid = register(client, "projet-desactive")

    response = client.post(
        f"/api/project/{project_uid}/api-security",
        json=submission(),
        headers=auth_headers(),
    )

    # 503 plutot qu'une liste vide : une liste vide se lirait « rien a
    # signaler », ce qui est exactement la confusion a eviter.
    assert response.status_code == 503


def test_capacite_annoncee_par_le_health(client):
    body = client.get("/api/security/health", headers=auth_headers()).json()
    assert body["api_security_enabled"] is True
    # Constat, pas promesse : cette analyse ne depend pas de Wazuh.
    assert body["requires_wazuh"] is False


# --------------------------------------------------------------------------
# Expurgation et confiance
# --------------------------------------------------------------------------


def test_une_preuve_en_clair_est_expurgee_a_l_entree(client):
    project_uid = register(client, "projet-expurgation")

    leaked = "AKIAIOSFODNN7EXAMPLE"
    client.post(
        f"/api/project/{project_uid}/api-security",
        json=submission(
            findings=[
                finding(
                    rule_id="API-CRED-001",
                    issue_type="hardcoded_api_credential",
                    evidence=f'"Authorization": "Bearer {leaked}"',
                )
            ]
        ),
        headers=auth_headers(),
    )

    stored = client.get(f"/api/project/{project_uid}/findings", headers=auth_headers()
    ).json()
    # Le backend n'accorde aucune confiance a l'expurgation du client : il
    # la refait, et c'est celle-la qui est ecrite.
    assert all(leaked not in item["evidence"] for item in stored)


def test_la_confiance_plafonne_la_gravite():
    # Une analyse par lignes ne voit que le fichier qu'on lui donne.
    # Afficher CRITICAL sur une preuve qui dit seulement « je n'ai pas vu
    # d'authentification ici » serait une affirmation que la preuve ne
    # soutient pas.
    assert api_security.apply_confidence("CRITICAL", "MEDIUM") == "HIGH"
    assert api_security.apply_confidence("CRITICAL", "LOW") == "MEDIUM"
    assert api_security.apply_confidence("HIGH", "LOW") == "MEDIUM"
    assert api_security.apply_confidence("LOW", "LOW") == "LOW"
    # Une detection formelle garde sa gravite.
    assert api_security.apply_confidence("CRITICAL", "HIGH") == "CRITICAL"


def test_l_empreinte_ne_porte_aucune_preuve():
    base = ApiFindingSubmission(**finding())
    autre_preuve = ApiFindingSubmission(**finding(evidence="tout autre chose"))
    autre_ligne = ApiFindingSubmission(**finding(line=99))

    # Le discriminant est la regle et le type, jamais la preuve : deux
    # analyses du meme fichier produisent la meme empreinte.
    assert api_security.fingerprint_of(base) == api_security.fingerprint_of(
        autre_preuve
    )
    # Deplacer la route change l'empreinte : le finding est recree, et une
    # decision « faux positif » ne suit pas la route d'une ligne a l'autre.
    assert api_security.fingerprint_of(base) != api_security.fingerprint_of(
        autre_ligne
    )


# --------------------------------------------------------------------------
# Reconciliation
# --------------------------------------------------------------------------


def test_un_second_passage_supprime_ce_qui_a_disparu(client):
    project_uid = register(client, "projet-reconciliation")

    client.post(
        f"/api/project/{project_uid}/api-security",
        json=submission(
            findings=[finding(line=10), finding(line=20, rule_id="API-CORS-002")]
        ),
        headers=auth_headers(),
    )
    assert len(client.get(f"/api/project/{project_uid}/findings", headers=auth_headers()
    ).json()) == 2

    # Le second probleme a ete corrige : il ne doit plus etre affiche.
    body = client.post(
        f"/api/project/{project_uid}/api-security",
        json=submission(findings=[finding(line=10)]),
        headers=auth_headers(),
    ).json()

    assert body["statistics"]["total"] == 1


def test_un_second_passage_ne_duplique_pas(client):
    project_uid = register(client, "projet-doublon")

    for _ in range(3):
        body = client.post(
            f"/api/project/{project_uid}/api-security", json=submission(),
        headers=auth_headers(),
    ).json()

    assert body["statistics"]["total"] == 1
    assert len(body["findings"]) == 1


def test_deux_regles_sur_la_meme_ligne_ne_comptent_qu_une_fois(client):
    project_uid = register(client, "projet-dedup")

    body = client.post(
        f"/api/project/{project_uid}/api-security",
        # Meme regle, meme ligne, meme type : un seul probleme.
        json=submission(findings=[finding(), finding()]),
        headers=auth_headers(),
    ).json()

    assert body["statistics"]["total"] == 1


def test_le_plafond_serveur_annonce_la_troncature(client, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "api_max_findings", 2)
    project_uid = register(client, "projet-plafond")

    body = client.post(
        f"/api/project/{project_uid}/api-security",
        json=submission(findings=[finding(line=n) for n in range(1, 6)]),
        headers=auth_headers(),
    ).json()

    assert body["statistics"]["truncated"] is True
    # Un decompte plafonne presente comme complet serait un mensonge.
    assert any("tronqu" in warning for warning in body["warnings"])


# --------------------------------------------------------------------------
# Contexte et cloisonnement
# --------------------------------------------------------------------------


def test_les_statistiques_rejoignent_le_contexte(client):
    project_uid = register(client, "projet-contexte")

    client.post(
        f"/api/project/{project_uid}/index",
        json={
            "files": [{"path": "src/api.py", "size": 10, "mtime": None,
                       "content_hash": None}],
            "manifests": [],
            "git": {"detected": False, "remote_host": None},
            "discovered_count": 1,
            "truncated": False,
            "warnings": [],
            "discovery_version": "1.0.0",
        },
        headers=auth_headers(),
    )
    client.post(f"/api/project/{project_uid}/api-security", json=submission(),
        headers=auth_headers(),
    )

    context = client.get(f"/api/project/{project_uid}/context", headers=auth_headers()
    ).json()
    assert context["api_statistics"]["total"] == 1
    assert context["api_statistics"]["endpoints_detected"] == 5
    # Un balayage d'API ne doit pas effacer ce qu'on sait des secrets.
    assert context["secret_statistics"]["total"] == 0


def test_deux_projets_ne_melangent_pas_leurs_findings(client):
    premier = register(client, "projet-alpha")
    second = register(client, "projet-beta")

    client.post(f"/api/project/{premier}/api-security", json=submission(),
        headers=auth_headers(),
    )
    client.post(
        f"/api/project/{second}/api-security",
        json=submission(findings=[finding(file_path="autre/routes.py", line=7)]),
        headers=auth_headers(),
    )

    findings_premier = client.get(f"/api/project/{premier}/findings", headers=auth_headers()
    ).json()
    findings_second = client.get(f"/api/project/{second}/findings", headers=auth_headers()
    ).json()

    assert [item["file"] for item in findings_premier] == ["src/api.py"]
    assert [item["file"] for item in findings_second] == ["autre/routes.py"]


def test_un_balayage_d_api_ne_touche_pas_les_secrets(client):
    project_uid = register(client, "projet-cohabitation")

    client.post(
        f"/api/project/{project_uid}/secrets",
        json={
            "findings": [
                {
                    "rule_id": "openai-api-key",
                    "file_path": "src/config.py",
                    "line": 3,
                    "column": None,
                    "secret_type": "openai_api_key",
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "evidence_redacted": "sk-proj-********",
                    "title": "",
                    "description": "",
                    "remediation": "",
                    "references": [],
                }
            ],
            "scanned_files": 1,
            "skipped_files": 0,
            "engine": "secret-scanner",
            "engine_version": "1.0.0",
            "truncated": False,
            "warnings": [],
        },
        headers=auth_headers(),
    )
    client.post(f"/api/project/{project_uid}/api-security", json=submission(),
        headers=auth_headers(),
    )

    unified = client.get(f"/api/project/{project_uid}/findings", headers=auth_headers()
    ).json()
    categories = sorted(item["category"] for item in unified)

    # Les deux familles cohabitent : la reconciliation est par categorie.
    assert categories == ["API", "SECRET"]


# --------------------------------------------------------------------------
# Sans Wazuh
# --------------------------------------------------------------------------


def test_aucun_appel_wazuh_dans_le_module():
    """Constat verifie sur le code source, pas une promesse.

    Le module *parle* de Wazuh dans sa docstring — pour dire qu'il ne
    l'appelle pas. Le test porte donc sur ce qui s'execute : aucun import
    et aucun appel.
    """
    import inspect
    import re

    source = inspect.getsource(api_security)
    # Commentaires et docstrings retires : la garantie porte sur le code.
    code = re.sub(r'"""[\s\S]*?"""', "", source)
    code = re.sub(r"#.*$", "", code, flags=re.MULTILINE)

    assert "wazuh" not in code.lower()


@pytest.mark.parametrize("payload", [{}, {"findings": []}])
def test_une_soumission_minimale_est_acceptee(client, payload):
    project_uid = register(client, f"projet-minimal-{len(payload)}")

    response = client.post(
        f"/api/project/{project_uid}/api-security",
        json=payload,
        headers=auth_headers(),
    )

    # Un client d'une version anterieure ne doit pas faire echouer la
    # route : les champs absents prennent leur valeur par defaut.
    assert response.status_code == 200
    assert response.json()["statistics"]["total"] == 0


def test_le_modele_borne_les_champs_libres():
    """Un client defaillant ne doit pas pouvoir remplir la base.

    Le modele **refuse** au-dela de la borne plutot que de tronquer : une
    preuve tronquee en silence resterait affichee comme complete, et
    couper au milieu d'une valeur pourrait en laisser passer un fragment.
    """
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        ApiFindingSubmission(**finding(evidence="x" * 5000))

    # Une declaration ordinaire passe telle quelle.
    accepte = ApiScanSubmission(
        findings=[ApiFindingSubmission(**finding(evidence='@app.post("/x")'))]
    )
    assert accepte.findings[0].evidence == '@app.post("/x")'

    # Une longue suite opaque, en revanche, est expurgee : le validateur
    # d'expurgation ne fait pas la difference entre un extrait de
    # declaration et une valeur, et c'est le bon sens de l'erreur.
    masque = ApiFindingSubmission(**finding(evidence="x" * 200))
    assert len(masque.evidence) < 200
