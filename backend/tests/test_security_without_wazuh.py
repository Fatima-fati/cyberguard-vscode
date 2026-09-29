"""La securite projet fonctionne avec Wazuh completement arrete.

Pourquoi ce fichier existe
--------------------------

Le projet s'appelle « Wazuh Security » pour des raisons historiques. Ce
nom ne doit pas devenir une dependance : la detection de secrets,
l'inventaire des dependances et l'analyse de vulnerabilites sont des
fonctions de securite **du code**, sans rapport avec la supervision
d'infrastructure.

L'exigence est donc precise : ces trois capacites doivent repondre a
l'identique avec le Manager arrete, l'Indexer eteint et l'API Wazuh
injoignable. Wazuh pourra devenir une integration externe plus tard ; il
ne doit jamais devenir un prerequis.

Deux familles de verification, et les deux sont necessaires
-----------------------------------------------------------

- **statique** : le code source du paquet `app.security` ne nomme Wazuh
  nulle part. C'est ce qui empeche la dependance de reapparaitre par
  inadvertance lors d'une evolution ;
- **dynamique** : avec toute la couche Wazuh remplacee par des objets qui
  levent a la moindre sollicitation, les routes repondent normalement.
  C'est ce qui prouve qu'aucun chemin d'execution ne passe par la.
"""

import io
import re
import tokenize
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from tests.conftest import auth_headers

SECURITY_PACKAGE = Path(__file__).resolve().parent.parent / "app" / "security"

# Termes cherches dans le code source. `wazuh_client`, `indexer` et
# `manager` couvrent les trois portes d'entree existantes.
WAZUH_MARKERS = re.compile(
    r"\b(wazuh|indexer|wazuh_client|WazuhError|get_alerts)\b", re.IGNORECASE
)


def code_only(path: Path) -> list[tuple[int, str]]:
    """Lignes de code d'un fichier, commentaires et chaines retires.

    Passe par `tokenize` plutot que par une expression reguliere : une
    docstring peut contenir n'importe quoi, y compris du code d'exemple,
    et un filtrage textuel confondrait les deux. Ici, ce qui reste est
    exactement ce que l'interprete executera.
    """
    source = path.read_text(encoding="utf-8")
    par_ligne: dict[int, list[str]] = {}

    for jeton in tokenize.generate_tokens(io.StringIO(source).readline):
        if jeton.type in (tokenize.COMMENT, tokenize.STRING, tokenize.NL):
            continue
        if not jeton.string.strip():
            continue
        par_ligne.setdefault(jeton.start[0], []).append(jeton.string)

    return [(numero, " ".join(morceaux)) for numero, morceaux in par_ligne.items()]


class ExplosiveWazuh:
    """Double qui refuse tout.

    N'importe quel attribut sollicite leve. Un appel Wazuh accidentel
    depuis la securite projet ne peut donc pas passer inapercu : il
    produit une erreur immediate et nommee, pas un resultat degrade.
    """

    def __getattr__(self, name: str):
        raise AssertionError(
            f"La securite projet a sollicite Wazuh (« {name} ») : "
            "ces fonctions doivent tourner avec Wazuh completement arrete."
        )


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def wazuh_arrete(monkeypatch):
    """Simule un environnement ou Wazuh est absent de bout en bout.

    Le client est remplace, sa fabrique aussi, et les adresses de
    configuration sont videes : meme une tentative de connexion directe
    echouerait.
    """
    from app import poller, wazuh_client

    monkeypatch.setattr(wazuh_client, "_client", ExplosiveWazuh(), raising=False)
    monkeypatch.setattr(
        wazuh_client,
        "get_wazuh_client",
        lambda *args, **kwargs: ExplosiveWazuh(),
        raising=False,
    )
    monkeypatch.setattr(poller, "_controller", None, raising=False)
    monkeypatch.setattr(settings, "wazuh_api_url", "")
    monkeypatch.setattr(settings, "indexer_url", "")
    monkeypatch.setattr(settings, "wazuh_api_password", "")
    monkeypatch.setattr(settings, "indexer_password", "")
    return True


@pytest.fixture
def project(client, wazuh_arrete):
    uid = client.post(
        "/api/project/discover",
        json={"root_hash": "d" * 64, "project_name": "sans-wazuh"},
        headers=auth_headers(),
    ).json()["project_uid"]

    client.post(
        f"/api/project/{uid}/index",
        json={
            "files": [{"path": "backend/config.py", "size": 10}],
            "manifests": [],
            "git": {"detected": False},
            "discovered_count": 1,
        },
        headers=auth_headers(),
    )
    return uid


# --------------------------------------------------------------------------
# Verification statique
# --------------------------------------------------------------------------


class TestAucuneReferenceAuCodeWazuh:
    def test_le_paquet_securite_existe_et_est_inspecte(self):
        """Garde-fou du test lui-meme : un chemin faux le rendrait muet."""
        fichiers = list(SECURITY_PACKAGE.rglob("*.py"))
        assert len(fichiers) >= 6, f"Paquet introuvable ou vide : {SECURITY_PACKAGE}"

    def test_aucun_module_de_securite_ne_nomme_wazuh(self):
        """Ni import, ni appel, ni mention — dans le CODE.

        Les commentaires et les docstrings sont ecartes par `code_only`,
        et c'est volontaire : ils disent precisement « ce module n'appelle
        pas Wazuh », ce qu'on ne veut surtout pas interdire. Ce qui est
        verifie ici, ce sont les identifiants reellement executes.
        """
        fautifs: list[str] = []

        for fichier in SECURITY_PACKAGE.rglob("*.py"):
            for numero, ligne in code_only(fichier):
                if WAZUH_MARKERS.search(ligne):
                    fautifs.append(f"{fichier.name}:{numero} — {ligne.strip()}")

        assert not fautifs, (
            "Le moteur de securite projet ne doit dependre d'aucune route "
            "Wazuh :" + chr(10) + chr(10).join(fautifs)
        )

    def test_aucun_module_de_securite_n_importe_le_client_wazuh(self):
        for fichier in SECURITY_PACKAGE.rglob("*.py"):
            source = fichier.read_text(encoding="utf-8")
            assert "from app.wazuh_client" not in source, fichier.name
            assert "import wazuh_client" not in source, fichier.name
            assert "from app import poller" not in source, fichier.name


# --------------------------------------------------------------------------
# Verification dynamique
# --------------------------------------------------------------------------


class TestLesRoutesRepondentSansWazuh:
    def test_l_etat_du_moteur_repond(self, client, wazuh_arrete):
        response = client.get("/api/security/health", headers=auth_headers())

        assert response.status_code == 200
        # Constat annonce a l'extension, et verifie ici de deux facons.
        assert response.json()["requires_wazuh"] is False

    def test_l_enregistrement_d_un_projet_repond(self, client, wazuh_arrete):
        response = client.post(
            "/api/project/discover",
            json={"root_hash": "e" * 64, "project_name": "hors-wazuh"},
            headers=auth_headers(),
        )
        assert response.status_code == 200

    def test_un_balayage_de_secrets_aboutit(self, client, project):
        response = client.post(
            f"/api/project/{project}/secrets",
            json={
                "findings": [
                    {
                        "rule_id": "secret.openai_api_key",
                        "file_path": "backend/config.py",
                        "line": 24,
                        "secret_type": "openai_api_key",
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "evidence_redacted": "OpenAI API key detected: sk-proj-********",
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

        assert response.status_code == 200
        assert response.json()["statistics"]["total"] == 1

    def test_un_inventaire_de_dependances_aboutit(self, client, project):
        response = client.post(
            f"/api/project/{project}/dependencies",
            json={
                "dependencies": [
                    {
                        "name": "express",
                        "ecosystem": "npm",
                        "version": "4.18.2",
                        "direct": True,
                        "manifest": "package.json",
                        "source": "manifest",
                    }
                ],
                "manifests_read": 1,
                "truncated": False,
                "warnings": [],
                "inventory_version": "1.0.0",
                # Pas d'interrogation externe : ce test porte sur Wazuh,
                # pas sur le reseau.
                "check_vulnerabilities": False,
            },
            headers=auth_headers(),
        )

        assert response.status_code == 200
        assert response.json()["dependency_statistics"]["total"] == 1

    def test_la_liste_des_findings_repond(self, client, project):
        response = client.get(
            f"/api/project/{project}/findings", headers=auth_headers()
        )
        assert response.status_code == 200

    def test_le_contexte_de_projet_se_relit(self, client, project):
        response = client.get(
            f"/api/project/{project}/context", headers=auth_headers()
        )

        assert response.status_code == 200
        # Les quatre champs de la phase 2 sont presents et exploitables.
        payload = response.json()
        assert "secret_statistics" in payload
        assert "dependency_statistics" in payload
        assert "dependency_ecosystems" in payload
        assert "vulnerability_statistics" in payload

    def test_le_health_de_l_analyse_de_code_annonce_la_capacite(
        self, client, wazuh_arrete
    ):
        response = client.get("/api/code/health")

        assert response.status_code == 200
        assert response.json()["project_security_enabled"] is True


# --------------------------------------------------------------------------
# Le fournisseur de vulnerabilites n'est pas Wazuh non plus
# --------------------------------------------------------------------------


class TestLeFournisseurEstIndependant:
    def test_le_fournisseur_configure_n_est_pas_une_route_wazuh(self, client):
        payload = client.get(
            "/api/security/health", headers=auth_headers()
        ).json()

        assert payload["vulnerability_provider"] == "osv"
        assert "wazuh" not in payload["vulnerability_provider"].lower()

    def test_l_adresse_interrogee_est_une_base_publique(self):
        """Verifie sur la configuration, pas sur une intention ecrite."""
        assert "osv.dev" in settings.osv_api_url
        assert "wazuh" not in settings.osv_api_url.lower()
