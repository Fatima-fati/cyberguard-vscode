"""Routes du contexte de projet : /api/project/* (phase 1).

Trois preoccupations distinctes :

1. le contrat fonctionne — enregistrer, indexer, relire ;
2. deux projets restent separes — la garantie centrale de cette phase ;
3. rien de sensible n'entre en base — ni chemin absolu, ni contenu.
"""

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

from app import store
from app.code.schemas import content_hash_of
from app.config import settings
from app.main import app

from .conftest import auth_headers


def root_hash(path: str) -> str:
    """Empreinte d'une racine, comme l'extension la calcule."""
    return hashlib.sha256(path.encode("utf-8")).hexdigest()


HASH_A = root_hash("/home/dev/projet-a")
HASH_B = root_hash("/home/dev/projet-b")


@pytest.fixture
def client():
    with TestClient(app, headers=auth_headers()) as test_client:
        yield test_client


def register(client, name: str, digest: str) -> str:
    response = client.post(
        "/api/project/discover",
        json={
            "root_hash": digest,
            "project_name": name,
            "discovery_version": "1.0.0",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["project_uid"]


def submit(client, project_uid: str, payload: dict) -> dict:
    response = client.post(f"/api/project/{project_uid}/index", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


FULL_STACK_INDEX = {
    "files": [
        {"path": "frontend/src/App.tsx", "size": 1200, "content_hash": "h1"},
        {"path": "frontend/src/api.ts", "size": 800, "content_hash": "h2"},
        {"path": "frontend/package.json", "size": 400, "content_hash": "h3"},
        {"path": "backend/app/main.py", "size": 2000, "content_hash": "h4"},
        {"path": "backend/requirements.txt", "size": 120, "content_hash": "h5"},
        {"path": "backend/.env", "size": 300, "content_hash": "h6"},
        {"path": "backend/.env.example", "size": 300, "content_hash": "h7"},
        {"path": "Dockerfile", "size": 500, "content_hash": "h8"},
        {"path": "tests/test_main.py", "size": 600, "content_hash": "h9"},
        {"path": "README.md", "size": 5000, "content_hash": "h10"},
    ],
    "manifests": [
        {
            "path": "frontend/package.json",
            "ecosystem": "npm",
            "dependency_names": ["react", "react-dom"],
        },
        {
            "path": "backend/requirements.txt",
            "ecosystem": "pypi",
            "dependency_names": ["fastapi", "uvicorn"],
        },
    ],
    "git": {"detected": True, "remote_host": "github.com"},
    "discovered_count": 10,
    "truncated": False,
    "warnings": [],
    "discovery_version": "1.0.0",
}


# --------------------------------------------------------------------------
# Enregistrement
# --------------------------------------------------------------------------


def test_un_projet_est_enregistre_et_recoit_un_identifiant(client):
    response = client.post(
        "/api/project/discover",
        json={"root_hash": HASH_A, "project_name": "MonApplication"},
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body["project_uid"]) == 32
    assert body["project_name"] == "MonApplication"
    assert body["known"] is False
    assert body["status"] == "discovery"


def test_le_meme_dossier_retrouve_son_identifiant(client):
    """Reconciliation par `root_hash`, pas par un identifiant que
    l'extension devrait conserver : un projet reouvert retrouve ses scans
    et ses findings meme apres redemarrage de l'editeur."""
    premier = register(client, "MonApplication", HASH_A)
    response = client.post(
        "/api/project/discover",
        json={"root_hash": HASH_A, "project_name": "MonApplication"},
    )

    assert response.json()["project_uid"] == premier
    assert response.json()["known"] is True


def test_deux_dossiers_recoivent_deux_identifiants(client):
    assert register(client, "A", HASH_A) != register(client, "B", HASH_B)


@pytest.mark.parametrize(
    "digest",
    ["", "trop-court", "z" * 64, "a" * 63, "a" * 65, "/home/dev/projet"],
)
def test_un_root_hash_invalide_est_refuse(client, digest):
    """Le backend n'accepte qu'une empreinte : un chemin est refuse.

    C'est la garde qui empeche un chemin absolu d'entrer en base par ce
    champ.
    """
    response = client.post(
        "/api/project/discover", json={"root_hash": digest, "project_name": "X"}
    )
    assert response.status_code == 422


def test_un_nom_de_projet_qui_ressemble_a_un_chemin_est_reduit(client):
    """Seul le dernier segment est conserve : pas d'arborescence en base."""
    response = client.post(
        "/api/project/discover",
        json={"root_hash": HASH_A, "project_name": "C:/Users/dev/MonApplication"},
    )
    assert response.json()["project_name"] == "MonApplication"


def test_un_projet_sans_nom_recoit_un_nom_neutre(client):
    """Il faut afficher quelque chose, et ce quelque chose ne revele rien."""
    response = client.post("/api/project/discover", json={"root_hash": HASH_A})
    assert response.json()["project_name"] == f"projet-{HASH_A[:8]}"


# --------------------------------------------------------------------------
# Index et contexte
# --------------------------------------------------------------------------


def test_un_index_produit_un_contexte_complet(client):
    project_uid = register(client, "MonApplication", HASH_A)
    context = submit(client, project_uid, FULL_STACK_INDEX)

    assert context["project_uid"] == project_uid
    assert context["project_name"] == "MonApplication"
    assert context["status"] == "ready"

    langues = {item["language"] for item in context["languages"]}
    assert langues == {"typescript", "python"}

    frameworks = {item["framework"] for item in context["frameworks"]}
    assert frameworks == {"React", "FastAPI"}

    assert "Full-stack" in context["project_types"]
    assert context["git_repository_detected"] is True
    assert context["git_remote_host"] == "github.com"
    assert context["last_discovery"]


def test_les_fichiers_sont_classes_par_nature(client):
    project_uid = register(client, "MonApplication", HASH_A)
    context = submit(client, project_uid, FULL_STACK_INDEX)

    manifestes = {item["path"] for item in context["manifests"]}
    assert manifestes == {"frontend/package.json", "backend/requirements.txt"}

    sensibles = {item["path"] for item in context["security_sensitive_files"]}
    # `.env` est sensible, `.env.example` ne l'est pas.
    assert sensibles == {"backend/.env"}

    config = {item["path"] for item in context["configuration_files"]}
    assert "Dockerfile" in config

    stats = context["file_statistics"]
    assert stats["indexed"] == 10
    assert stats["sensitive"] == 1
    assert stats["tests"] == 1


def test_un_fichier_sensible_porte_sa_raison_jamais_son_contenu(client):
    project_uid = register(client, "MonApplication", HASH_A)
    context = submit(client, project_uid, FULL_STACK_INDEX)

    env = context["security_sensitive_files"][0]
    assert env["path"] == "backend/.env"
    assert env["type"] == "environment-secrets"
    assert env["reason"] == "peut contenir des identifiants"
    # Aucun champ de contenu n'existe dans le contrat.
    assert set(env) == {"path", "kind", "type", "reason"}


def test_le_contexte_est_relisible(client):
    project_uid = register(client, "MonApplication", HASH_A)
    produit = submit(client, project_uid, FULL_STACK_INDEX)

    relu = client.get(f"/api/project/{project_uid}/context")
    assert relu.status_code == 200
    # Relecture de l'instantane, pas recalcul : les deux reponses doivent
    # etre identiques, sinon l'utilisateur verrait deux verites.
    assert relu.json() == produit


def test_un_index_remplace_le_precedent(client):
    """Un fichier supprime du projet disparait du contexte.

    Fusionner laisserait un decompte qui ne decrit plus le projet reel.
    """
    project_uid = register(client, "MonApplication", HASH_A)
    submit(client, project_uid, FULL_STACK_INDEX)

    reduit = {
        **FULL_STACK_INDEX,
        "files": [{"path": "backend/app/main.py", "size": 2000}],
        "manifests": [],
        "discovered_count": 1,
    }
    context = submit(client, project_uid, reduit)

    assert context["file_statistics"]["indexed"] == 1
    assert context["security_sensitive_files"] == []
    assert context["frameworks"] == []


def test_un_index_vide_est_accepte_sans_inventer_de_type(client):
    project_uid = register(client, "Vide", HASH_A)
    context = submit(
        client,
        project_uid,
        {"files": [], "manifests": [], "discovered_count": 0},
    )
    assert context["project_types"] == ["Unknown"]
    assert context["languages"] == []
    assert context["primary_language"] is None


def test_un_index_sur_un_projet_inconnu_repond_404(client):
    response = client.post(
        "/api/project/inexistant/index", json={"files": [], "manifests": []}
    )
    assert response.status_code == 404
    # Le message dit quoi faire, pas seulement ce qui a echoue.
    assert "discover" in response.json()["detail"]["detail"]


def test_un_contexte_absent_repond_404_en_distinguant_le_cas(client):
    """Deux 404 differents : la marche a suivre n'est pas la meme."""
    inconnu = client.get("/api/project/inexistant/context")
    assert inconnu.status_code == 404
    assert inconnu.json()["detail"]["error"] == "Projet inconnu"

    project_uid = register(client, "SansIndex", HASH_A)
    sans_index = client.get(f"/api/project/{project_uid}/context")
    assert sans_index.status_code == 404
    assert sans_index.json()["detail"]["error"] == "Contexte indisponible"


# --------------------------------------------------------------------------
# Plafonds et troncature
# --------------------------------------------------------------------------


def test_un_index_trop_grand_est_tronque_et_le_dit(client, monkeypatch):
    """Jamais de troncature silencieuse."""
    monkeypatch.setattr(settings, "project_max_indexed_files", 5)

    project_uid = register(client, "Gros", HASH_A)
    context = submit(
        client,
        project_uid,
        {
            "files": [{"path": f"src/f{n}.py", "size": 10} for n in range(20)],
            "manifests": [],
            "discovered_count": 20,
        },
    )

    assert context["file_statistics"]["indexed"] == 5
    assert context["file_statistics"]["truncated"] is True
    assert any("tronque" in warning for warning in context["warnings"])


def test_les_avertissements_de_l_extension_sont_transmis(client):
    """Ce que la decouverte n'a pas pu faire remonte a l'utilisateur."""
    project_uid = register(client, "MonApplication", HASH_A)
    context = submit(
        client,
        project_uid,
        {
            **FULL_STACK_INDEX,
            "warnings": ["3 fichiers ignores : taille superieure a la limite"],
        },
    )
    assert "3 fichiers ignores : taille superieure a la limite" in context["warnings"]


def test_les_listes_affichees_sont_bornees(client, monkeypatch):
    """Un monorepo peut contenir des centaines de manifestes."""
    monkeypatch.setattr(settings, "project_max_listed_files", 3)

    project_uid = register(client, "Monorepo", HASH_A)
    context = submit(
        client,
        project_uid,
        {
            "files": [
                {"path": f"packages/p{n}/package.json", "size": 10} for n in range(10)
            ],
            "manifests": [],
            "discovered_count": 10,
        },
    )
    assert len(context["manifests"]) == 3


# --------------------------------------------------------------------------
# Validation des entrees
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "C:/Windows/System32/config",
        "../../../etc/shadow",
        "src/../../secrets",
        "",
    ],
)
def test_un_chemin_absolu_ou_remontant_est_refuse(client, path):
    """L'index ne contient que des chemins relatifs a la racine du projet.

    Un chemin absolu revelerait l'arborescence du poste ; une remontee est
    le motif classique de traversee.
    """
    project_uid = register(client, "MonApplication", HASH_A)
    response = client.post(
        f"/api/project/{project_uid}/index",
        json={"files": [{"path": path, "size": 10}], "manifests": []},
    )
    assert response.status_code == 422


def test_une_url_de_remote_complete_est_refusee(client):
    """Seul l'hote est accepte : une URL de remote peut porter un jeton."""
    project_uid = register(client, "MonApplication", HASH_A)
    response = client.post(
        f"/api/project/{project_uid}/index",
        json={
            "files": [],
            "manifests": [],
            "git": {
                "detected": True,
                "remote_host": "https://jeton@github.com/org/depot.git",
            },
        },
    )
    assert response.status_code == 422


def test_les_noms_de_dependances_sont_assainis(client):
    """Une ligne de manifeste transmise par erreur n'entre pas comme un nom."""
    project_uid = register(client, "MonApplication", HASH_A)
    context = submit(
        client,
        project_uid,
        {
            "files": [{"path": "requirements.txt", "size": 10}],
            "manifests": [
                {
                    "path": "requirements.txt",
                    "ecosystem": "pypi",
                    "dependency_names": [
                        "fastapi",
                        "  ",
                        "--index-url https://user:mdp@depot.example/simple",
                        "flask",
                    ],
                }
            ],
            "discovered_count": 1,
        },
    )
    frameworks = {item["framework"] for item in context["frameworks"]}
    assert frameworks == {"FastAPI", "Flask"}
    # La ligne contenant des identifiants a ete ecartee : elle porte des
    # blancs, ce qu'un nom de paquet n'a jamais.
    assert "mdp" not in json.dumps(context)


# --------------------------------------------------------------------------
# Cloisonnement entre projets — la garantie centrale
# --------------------------------------------------------------------------


def test_deux_projets_ont_des_contextes_distincts(client):
    """Deux projets partageant `src/app.py` ne se contaminent pas."""
    uid_a = register(client, "ProjetA", HASH_A)
    uid_b = register(client, "ProjetB", HASH_B)

    submit(
        client,
        uid_a,
        {
            "files": [
                {"path": "src/app.py", "size": 100},
                {"path": "requirements.txt", "size": 50},
                {"path": ".env", "size": 20},
            ],
            "manifests": [
                {"path": "requirements.txt", "dependency_names": ["fastapi"]}
            ],
            "discovered_count": 3,
            "git": {"detected": True, "remote_host": "github.com"},
        },
    )
    submit(
        client,
        uid_b,
        {
            "files": [
                {"path": "src/app.py", "size": 100},
                {"path": "package.json", "size": 50},
            ],
            "manifests": [{"path": "package.json", "dependency_names": ["react"]}],
            "discovered_count": 2,
            "git": {"detected": False},
        },
    )

    context_a = client.get(f"/api/project/{uid_a}/context").json()
    context_b = client.get(f"/api/project/{uid_b}/context").json()

    assert context_a != context_b
    assert context_a["project_name"] == "ProjetA"
    assert context_b["project_name"] == "ProjetB"

    assert {i["framework"] for i in context_a["frameworks"]} == {"FastAPI"}
    assert {i["framework"] for i in context_b["frameworks"]} == {"React"}

    # Le `.env` de A n'apparait pas dans B.
    assert context_a["file_statistics"]["sensitive"] == 1
    assert context_b["file_statistics"]["sensitive"] == 0
    assert context_b["security_sensitive_files"] == []

    assert context_a["git_repository_detected"] is True
    assert context_b["git_repository_detected"] is False


def test_les_findings_sont_filtrables_par_projet(client):
    """Deux projets, le meme chemin de fichier, des findings separes.

    Sans ce filtre, `GET /api/code/findings` renvoyait les findings de tous
    les projets analyses par ce backend.
    """
    uid_a = register(client, "ProjetA", HASH_A)
    uid_b = register(client, "ProjetB", HASH_B)

    contenu_a = 'query = "SELECT * FROM users WHERE id=" + user_id\n'
    contenu_b = "response = requests.get(url, verify=False)\n"

    for uid, contenu, chemin in (
        (uid_a, contenu_a, "src/app.py"),
        (uid_b, contenu_b, "src/service.py"),
    ):
        response = client.post(
            "/api/code/scan",
            json={
                "file_path": chemin,
                "language": "python",
                "content": contenu,
                "content_hash": content_hash_of(contenu),
                "project_uid": uid,
            },
        )
        assert response.status_code == 200
        assert response.json()["findings_count"] >= 1

    findings_a = client.get(f"/api/code/findings?project_uid={uid_a}").json()
    findings_b = client.get(f"/api/code/findings?project_uid={uid_b}").json()

    assert findings_a
    assert findings_b
    assert {f["file_path"] for f in findings_a} == {"src/app.py"}
    assert {f["file_path"] for f in findings_b} == {"src/service.py"}

    # Sans filtre, les deux ressortent : le comportement historique est
    # conserve pour ne pas casser un appelant existant.
    assert len(client.get("/api/code/findings").json()) >= 2


def test_un_scan_sans_projet_reste_accepte(client):
    """Un fichier ouvert hors de tout dossier doit rester analysable."""
    contenu = "response = requests.get(url, verify=False)\n"
    response = client.post(
        "/api/code/scan",
        json={
            "file_path": "isole.py",
            "language": "python",
            "content": contenu,
            "content_hash": content_hash_of(contenu),
        },
    )
    assert response.status_code == 200
    assert response.json()["findings_count"] >= 1


# --------------------------------------------------------------------------
# Ce qui n'entre jamais en base
# --------------------------------------------------------------------------


def test_aucun_chemin_absolu_n_entre_en_base(client):
    """Verification sur la base elle-meme, pas sur la reponse HTTP."""
    project_uid = register(client, "MonApplication", HASH_A)
    submit(client, project_uid, FULL_STACK_INDEX)

    projet = store.get_project_by_uid(project_uid)
    serialise = json.dumps(projet)

    assert "/home/dev" not in serialise
    assert "C:/" not in serialise
    assert "C:\\\\" not in serialise
    # La racine n'est presente que sous forme d'empreinte.
    assert projet["root_hash"] == HASH_A

    fichiers = store.list_project_files(int(projet["id"]))
    for entry in fichiers:
        assert not entry["path"].startswith("/")
        assert ".." not in entry["path"]


def test_aucun_contenu_de_fichier_n_entre_en_base(client):
    """L'index porte une empreinte et une taille, jamais un octet de code."""
    project_uid = register(client, "MonApplication", HASH_A)
    submit(client, project_uid, FULL_STACK_INDEX)

    projet = store.get_project_by_uid(project_uid)
    colonnes = set(store.list_project_files(int(projet["id"]))[0])

    assert colonnes == {
        "id",
        "project_id",
        "path",
        "language",
        "kind",
        "size",
        "content_hash",
        "mtime",
        "indexed_at",
    }
    # Aucune colonne ne peut porter du contenu.
    assert "content" not in colonnes


def test_l_index_conserve_empreinte_et_taille(client):
    """Les metadonnees utiles a l'incrementiel des phases suivantes."""
    project_uid = register(client, "MonApplication", HASH_A)
    submit(client, project_uid, FULL_STACK_INDEX)

    projet = store.get_project_by_uid(project_uid)
    par_chemin = {
        entry["path"]: entry
        for entry in store.list_project_files(int(projet["id"]))
    }

    app_py = par_chemin["backend/app/main.py"]
    assert app_py["content_hash"] == "h4"
    assert app_py["size"] == 2000
    assert app_py["kind"] == "source"
    assert app_py["language"] == "python"

    assert par_chemin["backend/.env"]["kind"] == "sensitive"


def test_le_contexte_enregistre_ne_contient_aucun_secret(client):
    """L'instantane JSON est relu tel quel : il ne doit rien porter de plus."""
    project_uid = register(client, "MonApplication", HASH_A)
    submit(client, project_uid, FULL_STACK_INDEX)

    projet = store.get_project_by_uid(project_uid)
    instantane = store.get_project_context(int(projet["id"]))
    payload = json.loads(instantane["payload"])

    # Le chemin du `.env` est present — c'est utile a l'utilisateur, qui
    # sait ou est son fichier. Son contenu, lui, n'existe nulle part.
    assert payload["security_sensitive_files"][0]["path"] == "backend/.env"
    assert "content" not in instantane["payload"]


# --------------------------------------------------------------------------
# Authentification
# --------------------------------------------------------------------------


def test_toutes_les_routes_de_projet_exigent_le_jeton():
    """Y compris la lecture : le contexte decrit l'arborescence du projet."""
    with TestClient(app) as anonyme:
        assert anonyme.post("/api/project/discover", json={}).status_code == 401
        assert anonyme.post("/api/project/x/index", json={}).status_code == 401
        assert anonyme.get("/api/project/x/context").status_code == 401
