"""Tests de la posture de securite et du controle CI/CD (phase 8).

Ce que ces tests verrouillent :

    JAMAIS ANALYSE   un domaine jamais analyse porte `findings: null` et
                     l'etat `not_analyzed` — jamais un zero.
    COUVERTURE       balayage plafonne, index tronque, dependances non
                     verifiees, fournisseur muet, langage sans regles :
                     le domaine est `partial`, et le dit.
    DERNIER SCAN     un fichier reanalyse proprement ne compte plus ses
                     anciens findings de code.
    POLITIQUE        off / warn / block, conditions configurables ; un
                     blocage porte toujours ses raisons ; meme entree,
                     meme verdict.
    SURETE           ni preuve, ni secret, ni chemin absolu dans le
                     resultat CI.
    INDEPENDANCE     aucune IA, aucun Wazuh : le controle repond a
                     l'identique sans cle API et avec Wazuh injoignable.
    CLOISONNEMENT    un projet ne voit jamais les findings d'un autre.
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import store
from app.code.schemas import content_hash_of
from app.config import settings
from app.main import app
from app.security import posture as posture_service
from app.security.posture_schemas import SecurityPosture
from tests.conftest import auth_headers
from tests.test_security_ai import register, secret, submit_secrets

AREAS = ("secrets", "dependencies", "code", "api")


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Aucune sortie reseau : ni OSV, ni fournisseur d'IA."""
    monkeypatch.setattr(settings, "dependency_vulnerability_enabled", False)
    monkeypatch.setattr(settings, "openai_api_key", "")


# --------------------------------------------------------------------------
# Fabriques
# --------------------------------------------------------------------------


def index(client, uid, files, truncated=False, discovered=None):
    response = client.post(
        f"/api/project/{uid}/index",
        json={
            "files": [
                {"path": path, "size": 100, "content_hash": None, "mtime": None}
                for path in files
            ],
            "manifests": [],
            "git": {"detected": False, "remote_host": None},
            "discovered_count": discovered if discovered is not None else len(files),
            "truncated": truncated,
            "warnings": [],
            "discovery_version": "1.0.0",
        },
        headers=auth_headers(),
    )
    assert response.status_code == 200, response.text


def api_scan(client, uid, findings=(), endpoints=3):
    response = client.post(
        f"/api/project/{uid}/api-security",
        json={
            "findings": list(findings),
            "scanned_files": 2,
            "endpoints_detected": endpoints,
            "engine": "api-scanner",
            "engine_version": "1.0.0",
            "truncated": False,
            "warnings": [],
        },
        headers=auth_headers(),
    )
    assert response.status_code == 200, response.text


def inventory(client, uid, dependencies=()):
    response = client.post(
        f"/api/project/{uid}/dependencies",
        json={
            "dependencies": list(dependencies),
            "manifests_read": 1 if dependencies else 0,
            "truncated": False,
            "warnings": [],
            "inventory_version": "1.0.0",
            "check_vulnerabilities": False,
        },
        headers=auth_headers(),
    )
    assert response.status_code == 200, response.text


def code_scan(client, uid, path, content):
    response = client.post(
        "/api/code/scan",
        json={
            "file_path": path,
            "language": "python",
            "content": content,
            "content_hash": content_hash_of(content),
            "workspace": "demo",
            "project_uid": uid,
        },
        headers=auth_headers(),
    )
    assert response.status_code == 200, response.text
    return response.json()


def posture(client, uid) -> dict:
    response = client.get(f"/api/project/{uid}/posture", headers=auth_headers())
    assert response.status_code == 200, response.text
    return response.json()


def ci(client, uid, **policy) -> dict:
    response = client.post(
        f"/api/project/{uid}/ci-check", json=policy or None, headers=auth_headers()
    )
    assert response.status_code == 200, response.text
    return response.json()


def area(body: dict, name: str) -> dict:
    return next(item for item in body["areas"] if item["area"] == name)


CLEAN_PY = "def hello():\n    return 'bonjour'\n"
TLS_PY = "import requests\n\nresponse = requests.get(url, verify=False)\n"


def complete_project(client, name="projet-complet") -> str:
    """Projet dont les quatre domaines ont ete analyses sans finding."""
    uid = register(client, name)
    index(client, uid, ["src/app.py", "README.md"])
    submit_secrets(client, uid, [])
    api_scan(client, uid)
    inventory(client, uid)
    code_scan(client, uid, "src/app.py", CLEAN_PY)
    return uid


# --------------------------------------------------------------------------
# « Jamais analyse » contre « zero finding »
# --------------------------------------------------------------------------


def test_un_projet_jamais_analyse_n_affiche_aucun_zero(client):
    uid = register(client, "projet-vierge")

    body = posture(client, uid)

    assert body["analysis"] == "not_analyzed"
    for name in AREAS:
        domaine = area(body, name)
        assert domaine["state"] == "not_analyzed", name
        # L'absence est dite par `null`, jamais par 0.
        assert domaine["findings"] is None, name
        assert domaine["warnings"], name
    assert body["coverage"]["context_available"] is False


def test_zero_finding_apres_analyse_n_est_pas_jamais_analyse(client):
    uid = register(client, "projet-secret-propre")
    index(client, uid, ["src/app.py"])
    submit_secrets(client, uid, [])

    body = posture(client, uid)
    secrets = area(body, "secrets")

    assert secrets["state"] == "no_findings"
    assert secrets["findings"]["total"] == 0
    assert secrets["last_scan"] is not None
    # Les autres domaines, eux, n'ont jamais ete analyses.
    assert area(body, "api")["findings"] is None
    assert body["analysis"] == "partial"


def test_un_projet_analyse_sans_finding_est_complet(client):
    uid = complete_project(client)

    body = posture(client, uid)

    assert body["analysis"] == "complete", body
    assert body["findings"]["total"] == 0
    for name in AREAS:
        assert area(body, name)["state"] == "no_findings", name
        assert area(body, name)["coverage"] == "complete", name


def test_la_posture_ne_porte_aucun_score():
    """Ni score, ni note, ni indice : une lecture explicable, pas un verdict."""
    interdits = {"score", "security_score", "grade", "rating", "risk_score", "index"}

    def champs(model) -> set[str]:
        names = set(model.model_fields)
        for field in model.model_fields.values():
            annotation = field.annotation
            if hasattr(annotation, "model_fields"):
                names |= champs(annotation)
        return names

    assert not (champs(SecurityPosture) & interdits)


# --------------------------------------------------------------------------
# Findings et gravites
# --------------------------------------------------------------------------


def test_les_findings_sont_comptes_par_gravite_et_par_domaine(client):
    uid = register(client, "projet-findings")
    index(client, uid, ["backend/config.py"])
    submit_secrets(
        client,
        uid,
        [
            secret(severity="CRITICAL", confidence="HIGH"),
            secret(line=40, secret_type="aws_access_key", severity="HIGH", confidence="HIGH"),
        ],
    )
    api_scan(
        client,
        uid,
        [
            {
                "rule_id": "API-CORS-001",
                "file_path": "src/api.py",
                "line": 3,
                "issue_type": "wildcard_cors",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "evidence": "allow_origins=['*']",
                "title": "CORS ouvert",
            }
        ],
    )

    body = posture(client, uid)

    assert body["findings"]["critical"] == 1
    assert body["findings"]["high"] == 1
    assert body["findings"]["medium"] == 1
    assert body["findings"]["total"] == 3
    assert area(body, "secrets")["state"] == "findings"
    assert area(body, "secrets")["findings"]["total"] == 2
    assert area(body, "api")["findings"]["total"] == 1


def test_seul_le_dernier_scan_de_code_compte(client):
    """Un fichier corrige ne doit plus afficher ses anciens problemes."""
    uid = register(client, "projet-code")
    index(client, uid, ["src/client.py"])

    code_scan(client, uid, "src/client.py", TLS_PY)
    avant = area(posture(client, uid), "code")
    assert avant["findings"]["total"] >= 1

    code_scan(client, uid, "src/client.py", CLEAN_PY)
    apres = area(posture(client, uid), "code")

    assert apres["state"] == "no_findings"
    assert apres["findings"]["total"] == 0
    assert apres["metrics"]["files_scanned"] == 1


def backdate_code_scans(uid: str) -> None:
    """Place les scans du projet avant tout index soumis ensuite."""
    with store.get_connection() as connection:
        connection.execute(
            "UPDATE code_scans SET last_seen_at = '2000-01-01T00:00:00+00:00' "
            "WHERE project_uid = ?",
            (uid,),
        )


def test_un_fichier_ramene_a_un_contenu_deja_analyse_ne_compte_plus_l_ancien_probleme(client):
    """Regression : le cache (fichier, empreinte) ne cree aucun scan pour un
    contenu deja vu. Revenir a la version saine laissait le scan fautif
    « dernier », et la CI bloquait sur un probleme corrige."""
    uid = register(client, "projet-retour-arriere")
    index(client, uid, ["src/client.py"])

    code_scan(client, uid, "src/client.py", CLEAN_PY)
    code_scan(client, uid, "src/client.py", TLS_PY)
    assert area(posture(client, uid), "code")["findings"]["total"] >= 1

    retour = code_scan(client, uid, "src/client.py", CLEAN_PY)
    assert retour["cached"] is True

    code = area(posture(client, uid), "code")
    assert code["findings"]["total"] == 0
    assert code["metrics"]["files_scanned"] == 1
    verdict = ci(client, uid, mode="block")
    assert verdict["counts_by_area"]["code"] == 0
    assert not verdict["blocking_findings"]


def test_l_historique_courant_suit_le_retour_a_un_contenu_deja_analyse(client):
    """La reprise de l'extension au demarrage lit `current_only` : sans lui,
    elle reprendrait le scan fautif, le seul qui ait des lignes."""
    uid = register(client, "projet-historique-courant")
    code_scan(client, uid, "src/client.py", CLEAN_PY)
    code_scan(client, uid, "src/client.py", TLS_PY)
    code_scan(client, uid, "src/client.py", CLEAN_PY)

    def lister(**extra):
        response = client.get(
            "/api/code/findings",
            params={"project_uid": uid, "status": "open", **extra},
            headers=auth_headers(),
        )
        assert response.status_code == 200, response.text
        return response.json()

    assert lister(), "l'historique complet reste disponible"
    assert lister(current_only="true") == []


def test_un_fichier_supprime_ne_compte_plus_apres_un_nouvel_index(client):
    """Regression : un fichier supprime n'est jamais reanalyse ; son dernier
    scan bloquait la CI indefiniment."""
    uid = register(client, "projet-suppression")
    index(client, uid, ["src/app.py", "src/client.py"])
    code_scan(client, uid, "src/app.py", CLEAN_PY)
    code_scan(client, uid, "src/client.py", TLS_PY)
    backdate_code_scans(uid)

    index(client, uid, ["src/app.py"])

    code = area(posture(client, uid), "code")
    assert code["findings"]["total"] == 0
    assert code["metrics"]["files_scanned"] == 1
    assert not ci(client, uid, mode="block")["blocking_findings"]


def test_un_fichier_analyse_apres_le_dernier_index_compte_toujours(client):
    """Absent de l'index mais analyse apres lui : un fichier cree depuis la
    derniere decouverte. Ses findings ne sont jamais masques."""
    uid = register(client, "projet-fichier-neuf")
    index(client, uid, ["src/app.py"])

    code_scan(client, uid, "src/nouveau.py", TLS_PY)

    assert area(posture(client, uid), "code")["findings"]["total"] >= 1


def test_un_index_tronque_ne_prouve_aucune_suppression(client):
    uid = register(client, "projet-index-tronque")
    index(client, uid, ["src/app.py", "src/client.py"])
    code_scan(client, uid, "src/client.py", TLS_PY)
    backdate_code_scans(uid)

    index(client, uid, ["src/app.py"], truncated=True, discovered=5000)

    assert area(posture(client, uid), "code")["findings"]["total"] >= 1


def test_un_scan_servi_a_un_autre_projet_ne_change_pas_l_etat_courant(client):
    """Le cache est partage entre projets ; l'etat courant ne l'est pas."""
    a = register(client, "projet-cache-a")
    b = register(client, "projet-cache-b")
    code_scan(client, a, "src/client.py", CLEAN_PY)
    code_scan(client, a, "src/client.py", TLS_PY)

    code_scan(client, b, "src/client.py", CLEAN_PY)

    assert area(posture(client, a), "code")["findings"]["total"] >= 1


def test_un_finding_ecarte_ne_compte_plus(client):
    uid = register(client, "projet-ecarte")
    index(client, uid, ["backend/config.py"])
    findings = submit_secrets(client, uid, [secret()])
    with store.get_connection() as connection:
        connection.execute(
            "UPDATE security_findings SET status = 'dismissed' WHERE finding_id = ?",
            (findings[0]["id"],),
        )

    assert area(posture(client, uid), "secrets")["findings"]["total"] == 0


# --------------------------------------------------------------------------
# Couverture partielle
# --------------------------------------------------------------------------


def test_un_balayage_plafonne_rend_le_domaine_partiel(client):
    uid = register(client, "projet-plafond")
    index(client, uid, ["src/app.py"])
    response = client.post(
        f"/api/project/{uid}/secrets",
        json={"findings": [], "scanned_files": 5, "truncated": True},
        headers=auth_headers(),
    )
    assert response.status_code == 200

    secrets = area(posture(client, uid), "secrets")

    assert secrets["coverage"] == "partial"
    assert any("plafonné" in item for item in secrets["warnings"])


def test_un_index_tronque_est_annonce(client):
    uid = register(client, "projet-tronque")
    index(client, uid, ["src/app.py"], truncated=True, discovered=5000)
    submit_secrets(client, uid, [])

    body = posture(client, uid)

    assert body["coverage"]["index_truncated"] is True
    assert body["analysis"] == "partial"
    assert area(body, "secrets")["coverage"] == "partial"


def test_un_langage_sans_regles_est_signale(client):
    uid = register(client, "projet-go")
    index(client, uid, ["cmd/main.go", "src/app.py"])
    code_scan(client, uid, "src/app.py", CLEAN_PY)

    body = posture(client, uid)
    code = area(body, "code")

    assert body["coverage"]["unsupported_languages"] == ["go"]
    assert code["coverage"] == "partial"
    assert any("go" in item for item in code["warnings"])


def test_des_fichiers_source_non_analyses_rendent_le_code_partiel(client):
    uid = register(client, "projet-code-partiel")
    index(client, uid, ["src/a.py", "src/b.py", "src/c.py"])
    code_scan(client, uid, "src/a.py", CLEAN_PY)

    code = area(posture(client, uid), "code")

    assert code["coverage"] == "partial"
    assert code["metrics"] == {"files_scanned": 1, "supported_source_files": 3}


def test_un_fournisseur_de_vulnerabilites_muet_rend_les_dependances_partielles(client):
    uid = register(client, "projet-fournisseur-muet")
    index(client, uid, ["package.json"])
    inventory(
        client,
        uid,
        [
            {
                "name": "express",
                "ecosystem": "npm",
                "version": "4.17.1",
                "direct": True,
                "manifest": "package.json",
                "source": "manifest",
            }
        ],
    )

    body = posture(client, uid)
    dependencies = area(body, "dependencies")

    assert dependencies["coverage"] == "partial"
    assert body["coverage"]["vulnerability_check_conclusive"] is False
    assert body["coverage"]["vulnerability_provider_status"] != "available"
    # Aucun finding, mais pas « aucune vulnerabilite » : la couverture le dit.
    assert dependencies["findings"]["total"] == 0
    assert dependencies["warnings"]

    result = ci(client, uid)
    condition = next(
        item for item in result["conditions"]
        if item["code"] == "vulnerability_provider_unavailable"
    )
    assert condition["triggered"] is True


def test_un_projet_sans_dependance_n_a_rien_a_faire_verifier(client):
    uid = complete_project(client, "projet-sans-dependance")

    result = ci(client, uid)
    condition = next(
        item for item in result["conditions"]
        if item["code"] == "vulnerability_provider_unavailable"
    )

    assert condition["triggered"] is False


def test_git_est_annonce_indisponible_cote_backend_sans_zero(client):
    uid = complete_project(client, "projet-git")

    git = area(posture(client, uid), "git")

    assert git["state"] == "unavailable"
    assert git["findings"] is None
    assert git["warnings"]


def test_l_historique_insuffisant_est_dit(client):
    uid = complete_project(client, "projet-historique")

    history = posture(client, uid)["history"]

    assert history["available"] is False
    assert "Historique insuffisant" in history["message"]


# --------------------------------------------------------------------------
# Cloisonnement
# --------------------------------------------------------------------------


def test_un_projet_ne_voit_jamais_les_findings_d_un_autre(client):
    premier = register(client, "posture-a")
    second = register(client, "posture-b")
    index(client, premier, ["backend/config.py"])
    index(client, second, ["backend/config.py"])
    submit_secrets(client, second, [secret(severity="CRITICAL", confidence="HIGH")])
    code_scan(client, second, "src/client.py", TLS_PY)

    body = posture(client, premier)
    result = ci(client, premier)

    assert body["findings"]["total"] == 0
    assert result["counts"]["total"] == 0
    assert result["blocking_findings"] == []


def test_un_projet_inconnu_repond_404(client):
    assert client.get("/api/project/inconnu/posture", headers=auth_headers()).status_code == 404
    assert client.post("/api/project/inconnu/ci-check", headers=auth_headers()).status_code == 404


def test_les_routes_exigent_le_jeton(client):
    uid = register(client, "posture-jeton")
    anonyme = TestClient(app)
    assert anonyme.get(f"/api/project/{uid}/posture").status_code == 401
    assert anonyme.post(f"/api/project/{uid}/ci-check").status_code == 401


# --------------------------------------------------------------------------
# Politique CI
# --------------------------------------------------------------------------


def risky_project(client, name="projet-risque") -> str:
    uid = register(client, name)
    index(client, uid, ["backend/config.py"])
    submit_secrets(client, uid, [secret(severity="CRITICAL", confidence="HIGH")])
    return uid


def test_mode_off_ne_bloque_rien_mais_mesure_tout(client):
    uid = risky_project(client, "ci-off")

    result = ci(client, uid, mode="off")

    assert result["status"] == "off"
    assert result["exit_decision"] == "pass"
    assert result["exit_code"] == 0
    assert result["reasons"] == []
    critical = next(item for item in result["conditions"] if item["code"] == "critical_findings")
    assert critical["triggered"] is True
    assert critical["action"] == "ignore"


def test_mode_warn_par_defaut_avertit_sans_bloquer(client):
    uid = risky_project(client, "ci-warn")

    result = ci(client, uid)

    assert result["policy"]["mode"] == "warn"
    assert result["status"] == "warning"
    assert result["exit_decision"] == "pass"
    assert result["exit_code"] == 0
    codes = {reason["code"] for reason in result["reasons"]}
    assert {"critical_findings", "secrets_present"} <= codes
    assert all(reason["action"] == "warn" for reason in result["reasons"])


def test_mode_block_bloque_et_dit_pourquoi(client):
    uid = risky_project(client, "ci-block")

    result = ci(client, uid, mode="block")

    assert result["status"] == "blocked"
    assert result["exit_decision"] == "fail"
    assert result["exit_code"] == 1
    bloquants = [reason for reason in result["reasons"] if reason["action"] == "block"]
    assert {reason["code"] for reason in bloquants} >= {"critical_findings", "secrets_present"}
    assert all(reason["message"] for reason in bloquants)
    assert result["blocking_findings"][0]["severity"] == "CRITICAL"
    assert result["blocking_findings"][0]["file"] == "backend/config.py"


def test_mode_block_ne_bloque_pas_sur_une_condition_d_avertissement(client):
    """Une analyse incomplete avertit ; elle ne bloque que si on le demande."""
    uid = register(client, "ci-incomplet")
    index(client, uid, ["src/app.py"])
    submit_secrets(client, uid, [])

    result = ci(client, uid, mode="block")

    assert result["status"] == "warning"
    assert result["exit_code"] == 0
    assert any(reason["code"] == "analysis_incomplete" for reason in result["reasons"])


def test_une_condition_d_avertissement_peut_devenir_bloquante(client):
    uid = register(client, "ci-incomplet-strict")

    result = ci(client, uid, mode="block", fail_on=["analysis_incomplete"])

    assert result["status"] == "blocked"
    assert result["exit_code"] == 1
    assert result["reasons"][0]["code"] == "analysis_incomplete"


def test_un_projet_complet_et_sans_finding_passe(client):
    uid = complete_project(client, "ci-vert")

    result = ci(client, uid, mode="block")

    assert result["status"] == "passed", result["reasons"]
    assert result["exit_code"] == 0
    assert result["analysis"] == "complete"


def test_la_politique_par_defaut_vient_de_la_configuration(client, monkeypatch):
    monkeypatch.setattr(settings, "ci_policy_mode", "block")
    monkeypatch.setattr(settings, "ci_fail_on", "high_findings, inconnu")
    uid = risky_project(client, "ci-config")

    result = ci(client, uid)

    assert result["policy"]["mode"] == "block"
    # Un nom inconnu est ignore, pas une erreur.
    assert result["policy"]["fail_on"] == ["high_findings"]
    # Aucun HIGH ici : le CRITICAL n'est pas dans fail_on, il n'est donc
    # pas bloquant sous cette politique.
    assert result["status"] in ("warning", "passed")


def test_un_mode_mal_orthographie_retombe_sur_warn(client, monkeypatch):
    monkeypatch.setattr(settings, "ci_policy_mode", "blok")
    uid = risky_project(client, "ci-faute")

    assert ci(client, uid)["policy"]["mode"] == "warn"


def test_une_condition_presente_dans_les_deux_listes_est_bloquante(client):
    uid = risky_project(client, "ci-doublon")

    result = ci(
        client, uid, mode="block",
        fail_on=["secrets_present"], warn_on=["secrets_present"],
    )

    assert result["policy"]["warn_on"] == []
    assert result["status"] == "blocked"


def test_une_politique_invalide_est_refusee(client):
    uid = register(client, "ci-invalide")
    response = client.post(
        f"/api/project/{uid}/ci-check",
        json={"mode": "panic", "fail_on": ["tout"]},
        headers=auth_headers(),
    )
    assert response.status_code == 422


def test_le_resultat_est_deterministe(client):
    uid = risky_project(client, "ci-deterministe")

    premier = ci(client, uid, mode="block")
    second = ci(client, uid, mode="block")
    for body in (premier, second):
        body.pop("generated_at")

    assert premier == second


def test_le_resultat_est_un_json_machine_stable(client):
    uid = risky_project(client, "ci-json")

    result = ci(client, uid)

    assert result["schema_version"] == "1.0"
    for key in (
        "project", "generated_at", "policy", "status", "exit_decision",
        "exit_code", "analysis", "counts", "counts_by_area", "conditions",
        "reasons", "incomplete_areas", "unsupported_languages",
        "vulnerability_provider_status", "blocking_findings",
    ):
        assert key in result, key
    assert set(result["project"]) == {"project_uid", "project_name"}
    assert result["requires_ai"] is False
    assert result["requires_wazuh"] is False
    # Aller-retour JSON sans perte.
    assert json.loads(json.dumps(result)) == result


# --------------------------------------------------------------------------
# Surete du resultat
# --------------------------------------------------------------------------


def test_aucun_secret_ni_preuve_ni_chemin_absolu_dans_le_resultat_ci(client):
    uid = risky_project(client, "ci-surete")
    fuite = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    with store.get_connection() as connection:
        connection.execute(
            "UPDATE security_findings SET title = ?, evidence = ?, file_path = ? "
            "WHERE project_uid = ?",
            (f"Jeton {fuite}", f"token={fuite}", "C:/Users/quelqu-un/projet/config.py", uid),
        )

    result = ci(client, uid, mode="block")
    brut = json.dumps(result)

    assert fuite not in brut
    assert "evidence" not in brut
    assert "C:/Users" not in brut
    assert "root_hash" not in brut
    assert result["blocking_findings"][0]["file"] is None


def test_la_posture_ne_porte_ni_preuve_ni_chemin(client):
    uid = risky_project(client, "posture-surete")

    brut = json.dumps(posture(client, uid))

    assert "evidence" not in brut
    assert "sk-proj" not in brut
    assert "backend/config.py" not in brut


# --------------------------------------------------------------------------
# Independance : ni IA, ni Wazuh
# --------------------------------------------------------------------------


def test_le_controle_ci_fonctionne_sans_ia(client, monkeypatch):
    """Aucun appel au fournisseur, meme configure."""
    from app.ai import openai_client

    def interdit(*args, **kwargs):
        raise AssertionError("le controle CI ne doit jamais appeler l'IA")

    monkeypatch.setattr(openai_client.OpenAIClient, "complete_json", interdit)
    uid = risky_project(client, "ci-sans-ia")

    assert ci(client, uid, mode="block")["status"] == "blocked"
    monkeypatch.setattr(settings, "openai_api_key", "sk-test-configuree")
    assert ci(client, uid, mode="block")["status"] == "blocked"


def test_le_controle_ci_fonctionne_sans_wazuh(client, monkeypatch):
    from app import wazuh_client

    def injoignable(*args, **kwargs):
        raise AssertionError("le controle CI ne doit jamais appeler Wazuh")

    monkeypatch.setattr(wazuh_client, "get_wazuh_client", injoignable)
    uid = risky_project(client, "ci-sans-wazuh")

    assert ci(client, uid)["status"] == "warning"
    assert posture(client, uid)["requires_wazuh"] is False


def test_le_code_de_la_posture_n_appelle_ni_ia_ni_wazuh_ni_n_ecrit():
    racine = Path(__file__).resolve().parent.parent / "app" / "security"
    for fichier in ("posture.py", "posture_schemas.py"):
        source = (racine / fichier).read_text(encoding="utf-8")
        for interdit in (
            "wazuh_client", "openai_client", "run_model", "app.ai.",
            "sync_security_findings", "INSERT ", "UPDATE ", "DELETE ",
        ):
            assert interdit not in source, f"{fichier} contient « {interdit} »"


@pytest.mark.asyncio
async def test_la_politique_se_resout_sans_requete():
    policy = posture_service.resolve_policy(None)
    assert policy.mode == "warn"
    assert "critical_findings" in policy.fail_on
    assert "analysis_incomplete" in policy.warn_on
