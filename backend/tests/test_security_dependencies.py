"""Tests de l'inventaire des dependances et de son analyse.

La propriete verifiee ici de bout en bout, et qui gouverne tout le module :

    verifiee et saine       le fournisseur a repondu, rien pour ce paquet
    verifiee et vulnerable  le fournisseur a repondu, voici quoi
    NON VERIFIEE            version non figee, ecosysteme non couvert, ou
                            fournisseur muet — on ne sait pas

Une dependance non verifiee n'est **jamais** comptee comme saine. Les
tests ci-dessous prennent chacun des chemins qui pourraient la faire
basculer du mauvais cote.
"""

import pytest
from fastapi.testclient import TestClient

from app import store
from app.config import settings
from app.main import app
from app.security.dependencies import deduplicate, queryable, record_inventory
from app.security.providers.base import (
    PackageQuery,
    PackageVulnerability,
    ProviderOutcome,
    VulnerabilityProvider,
)
from app.security.schemas import DependencyInventorySubmission, DependencyRecord
from tests.conftest import auth_headers


class FakeProvider(VulnerabilityProvider):
    """Fournisseur scripte : un etat, et des vulnerabilites par cle.

    Implemente la vraie interface plutot qu'un objet de circonstance : si
    le contrat change, ce double cesse de compiler, ce qui est exactement
    le signal qu'on veut.
    """

    name = "fake"

    def __init__(
        self,
        status: str = "available",
        vulnerabilities: dict | None = None,
        checked: set | None = None,
        ecosystems: set | None = None,
    ) -> None:
        self.status = status
        self._vulnerabilities = vulnerabilities or {}
        self._checked = checked
        self._ecosystems = ecosystems or {"npm", "pypi", "maven", "go", "composer"}
        self.received: list[PackageQuery] = []

    @property
    def supported_ecosystems(self) -> frozenset[str]:
        return frozenset(self._ecosystems)

    async def check(self, packages):
        self.received = list(packages)
        return ProviderOutcome(
            status=self.status,  # type: ignore[arg-type]
            vulnerabilities=self._vulnerabilities,
            checked=(
                self._checked
                if self._checked is not None
                else {package.key for package in packages}
            ),
        )


AVIS = PackageVulnerability(
    identifier="GHSA-29mw-wpgm-hmr9",
    summary="Deni de service par expression reguliere",
    severity="HIGH",
    fixed_version="4.19.2",
    aliases=("CVE-2024-29041",),
    references=("https://github.com/expressjs/express/security",),
)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def project(client):
    """Projet enregistre et indexe. Retourne (project_uid, project_id)."""
    uid = client.post(
        "/api/project/discover",
        json={"root_hash": "c" * 64, "project_name": "demo"},
        headers=auth_headers(),
    ).json()["project_uid"]

    client.post(
        f"/api/project/{uid}/index",
        json={
            "files": [{"path": "package.json", "size": 100}],
            "manifests": [],
            "git": {"detected": False},
            "discovered_count": 1,
        },
        headers=auth_headers(),
    )
    return uid, int(store.get_project_by_uid(uid)["id"])


def record(name: str, version: str = "", **overrides) -> DependencyRecord:
    payload = {
        "name": name,
        "ecosystem": "npm",
        "version": version,
        "direct": True,
        "manifest": "package.json",
        "source": "manifest",
    }
    payload.update(overrides)
    return DependencyRecord(**payload)


def inventory(*records: DependencyRecord, **overrides) -> DependencyInventorySubmission:
    payload = {
        "dependencies": list(records),
        "manifests_read": 1,
        "truncated": False,
        "warnings": [],
        "inventory_version": "1.0.0",
        "check_vulnerabilities": True,
    }
    payload.update(overrides)
    return DependencyInventorySubmission(**payload)


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------


class TestNormalisation:
    def test_le_lockfile_l_emporte_sur_le_manifeste(self):
        """Une version exacte vaut mieux qu'une contrainte.

        Garder les deux gonflerait le decompte et, surtout, ferait
        apparaitre le paquet comme non verifiable alors qu'il l'est.
        """
        resultat = deduplicate(
            [
                record("express", "", source="manifest"),
                record("express", "4.18.2", source="lockfile", direct=False),
            ]
        )

        assert len(resultat) == 1
        assert resultat[0].version == "4.18.2"

    def test_la_comparaison_des_noms_ignore_la_casse(self):
        resultat = deduplicate([record("Express", "1.0.0"), record("express", "1.0.0")])
        assert len(resultat) == 1

    def test_deux_ecosystemes_ne_se_confondent_pas(self):
        """`requests` existe en PyPI et en RubyGems : ce sont deux paquets."""
        resultat = deduplicate(
            [
                record("requests", "2.0.0", ecosystem="pypi"),
                record("requests", "2.0.0", ecosystem="rubygems"),
            ]
        )
        assert len(resultat) == 2

    def test_l_ordre_est_stable(self):
        """Deux inventaires identiques doivent produire la meme liste."""
        entrees = [record("zeta", "1.0.0"), record("alpha", "1.0.0")]
        assert [item.name for item in deduplicate(entrees)] == ["alpha", "zeta"]


class TestInterrogeable:
    def test_une_contrainte_n_est_pas_interrogeable(self):
        """« Cet intervalle est-il vulnerable ? » n'a pas de reponse utile."""
        assert queryable([record("express", "")], FakeProvider()) == []

    def test_un_ecosysteme_non_couvert_n_est_pas_interroge(self):
        provider = FakeProvider(ecosystems={"npm"})
        entrees = [
            record("express", "4.18.2", ecosystem="npm"),
            record("mon-paquet", "1.0.0", ecosystem="nuget"),
        ]

        assert [item.name for item in queryable(entrees, provider)] == ["express"]


# --------------------------------------------------------------------------
# Chaine complete
# --------------------------------------------------------------------------


class TestAnalyse:
    @pytest.mark.asyncio
    async def test_un_paquet_vulnerable_produit_un_finding_actionnable(self, project):
        uid, project_id = project
        vulnerable = record("express", "4.17.1")
        provider = FakeProvider(vulnerabilities={vulnerable.key: [AVIS]})

        result = await record_inventory(uid, project_id, inventory(vulnerable), provider)

        assert result.vulnerability_statistics.total == 1
        assert result.vulnerability_statistics.conclusive is True
        assert result.dependency_statistics.vulnerable == 1

        (finding,) = result.findings
        assert finding.category == "DEPENDENCY"
        assert finding.severity == "HIGH"
        # La detection n'est pas heuristique : c'est une correspondance
        # exacte entre une version et un avis publie.
        assert finding.confidence == "HIGH"
        assert "4.19.2" in finding.remediation
        assert "CVE-2024-29041" in finding.references
        assert finding.file == "package.json"

    @pytest.mark.asyncio
    async def test_un_paquet_sain_et_verifie_est_compte_comme_verifie(self, project):
        uid, project_id = project
        sain = record("lodash", "4.17.21")

        result = await record_inventory(uid, project_id, inventory(sain), FakeProvider())

        assert result.findings == []
        assert result.dependency_statistics.vulnerable == 0
        # La seule situation ou l'on peut conclure quoi que ce soit.
        assert result.dependency_statistics.unverified == 0
        assert result.vulnerability_statistics.conclusive is True

    @pytest.mark.asyncio
    async def test_une_version_non_figee_est_comptee_non_verifiee(self, project):
        uid, project_id = project
        flou = record("express", "")

        result = await record_inventory(uid, project_id, inventory(flou), FakeProvider())

        assert result.dependency_statistics.total == 1
        # Ni vulnerable ni saine : inconnue.
        assert result.dependency_statistics.vulnerable == 0
        assert result.dependency_statistics.unverified == 1

    @pytest.mark.asyncio
    async def test_un_ecosysteme_non_couvert_est_compte_non_verifie(self, project):
        uid, project_id = project
        exotique = record("mon-paquet", "1.0.0", ecosystem="nuget")
        provider = FakeProvider(ecosystems={"npm"})

        result = await record_inventory(
            uid, project_id, inventory(exotique), provider
        )

        assert result.dependency_statistics.unverified == 1

    @pytest.mark.asyncio
    async def test_les_directes_et_transitives_sont_distinguees(self, project):
        uid, project_id = project

        result = await record_inventory(
            uid,
            project_id,
            inventory(
                record("express", "4.18.2", direct=True),
                record("cookie", "0.5.0", direct=False),
            ),
            FakeProvider(),
        )

        assert result.dependency_statistics.total == 2
        assert result.dependency_statistics.direct == 1
        assert result.dependency_statistics.transitive == 1


# --------------------------------------------------------------------------
# Fournisseur muet : le coeur de l'honnetete de cette phase
# --------------------------------------------------------------------------


class TestFournisseurMuet:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "status", ["unavailable", "timeout", "rate_limited", "error", "disabled"]
    )
    async def test_aucun_etat_non_concluant_ne_declare_une_dependance_saine(
        self, project, status
    ):
        uid, project_id = project
        provider = FakeProvider(status=status, checked=set())

        result = await record_inventory(
            uid, project_id, inventory(record("express", "4.18.2")), provider
        )

        assert result.vulnerability_statistics.conclusive is False
        # La dependance existe, elle n'est pas vulnerable a notre
        # connaissance, et surtout : personne n'a pu regarder.
        assert result.dependency_statistics.unverified == 1
        assert result.dependency_statistics.vulnerable == 0

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "status", ["unavailable", "timeout", "rate_limited", "error", "disabled"]
    )
    async def test_le_message_ne_dit_jamais_aucune_vulnerabilite(
        self, project, status
    ):
        uid, project_id = project
        provider = FakeProvider(status=status, checked=set())

        result = await record_inventory(
            uid, project_id, inventory(record("express", "4.18.2")), provider
        )

        message = result.vulnerability_statistics.message.lower()
        assert "impossible de vérifier" in message or "désactivée" in message
        assert "aucune vulnérabilité" not in message

    @pytest.mark.asyncio
    async def test_un_fournisseur_muet_produit_un_avertissement_affiche(
        self, project
    ):
        """Une verification qui n'a pas eu lieu doit se voir, pas seulement
        se journaliser."""
        uid, project_id = project
        provider = FakeProvider(status="unavailable", checked=set())

        result = await record_inventory(
            uid, project_id, inventory(record("express", "4.18.2")), provider
        )

        assert result.warnings

    @pytest.mark.asyncio
    async def test_l_inventaire_survit_a_un_fournisseur_injoignable(self, project):
        """L'inventaire vaut par lui-meme.

        « Ce projet tire 412 dependances, dont 38 directes » reste une
        information utile meme quand le reseau est coupe. La perdre serait
        une regression fonctionnelle.
        """
        uid, project_id = project
        provider = FakeProvider(status="unavailable", checked=set())

        result = await record_inventory(
            uid,
            project_id,
            inventory(record("express", "4.18.2"), record("lodash", "4.17.21")),
            provider,
        )

        assert result.dependency_statistics.total == 2
        assert len(store.list_project_dependencies(project_id)) == 2

    @pytest.mark.asyncio
    async def test_la_base_distingue_verifie_de_non_regarde(self, project):
        """Sans ce drapeau, les deux seraient indiscernables en table."""
        uid, project_id = project

        await record_inventory(
            uid, project_id, inventory(record("express", "4.18.2")), FakeProvider()
        )
        (ligne,) = store.list_project_dependencies(project_id)
        assert ligne["verified"] == 1

        await record_inventory(
            uid,
            project_id,
            inventory(record("express", "4.18.2")),
            FakeProvider(status="timeout", checked=set()),
        )
        (ligne,) = store.list_project_dependencies(project_id)
        assert ligne["verified"] == 0


# --------------------------------------------------------------------------
# Consentement a la sortie reseau
# --------------------------------------------------------------------------


class TestConsentement:
    @pytest.mark.asyncio
    async def test_le_client_peut_refuser_l_interrogation(self, project):
        """Le client demande, le serveur decide — et ici le client ne
        demande pas."""
        uid, project_id = project
        provider = FakeProvider()

        result = await record_inventory(
            uid,
            project_id,
            inventory(record("express", "4.18.2"), check_vulnerabilities=False),
            provider,
        )

        assert provider.received == []
        assert result.vulnerability_statistics.provider_status == "disabled"
        assert result.dependency_statistics.unverified == 1

    @pytest.mark.asyncio
    async def test_seuls_le_nom_l_ecosysteme_et_la_version_sont_soumis(self, project):
        """Le chemin du manifeste ne sort pas de la machine."""
        uid, project_id = project
        provider = FakeProvider()

        await record_inventory(
            uid,
            project_id,
            inventory(record("express", "4.18.2", manifest="apps/web/package.json")),
            provider,
        )

        (soumis,) = provider.received
        assert soumis == PackageQuery(
            name="express", ecosystem="npm", version="4.18.2"
        )


# --------------------------------------------------------------------------
# Bornes et persistance
# --------------------------------------------------------------------------


class TestBornesEtPersistance:
    @pytest.mark.asyncio
    async def test_le_plafond_serveur_est_applique_et_annonce(
        self, project, monkeypatch
    ):
        uid, project_id = project
        monkeypatch.setattr(settings, "project_max_dependencies", 2)

        result = await record_inventory(
            uid,
            project_id,
            inventory(*(record(f"paquet-{index}", "1.0.0") for index in range(10))),
            FakeProvider(),
        )

        assert result.dependency_statistics.total == 2
        assert result.dependency_statistics.truncated is True
        assert any("tronque" in warning for warning in result.warnings)

    @pytest.mark.asyncio
    async def test_une_dependance_retiree_disparait_de_l_inventaire(self, project):
        uid, project_id = project

        await record_inventory(
            uid,
            project_id,
            inventory(record("express", "4.18.2"), record("lodash", "4.17.21")),
            FakeProvider(),
        )
        result = await record_inventory(
            uid, project_id, inventory(record("express", "4.18.2")), FakeProvider()
        )

        assert result.dependency_statistics.total == 1

    @pytest.mark.asyncio
    async def test_une_vulnerabilite_corrigee_disparait_des_findings(self, project):
        uid, project_id = project
        vulnerable = record("express", "4.17.1")
        corrige = record("express", "4.19.2")

        await record_inventory(
            uid,
            project_id,
            inventory(vulnerable),
            FakeProvider(vulnerabilities={vulnerable.key: [AVIS]}),
        )
        result = await record_inventory(
            uid, project_id, inventory(corrige), FakeProvider()
        )

        assert result.findings == []

    @pytest.mark.asyncio
    async def test_les_volumes_par_ecosysteme_montrent_la_zone_d_ombre(self, project):
        uid, project_id = project
        provider = FakeProvider(ecosystems={"npm"})

        result = await record_inventory(
            uid,
            project_id,
            inventory(
                record("express", "4.18.2", ecosystem="npm"),
                record("com.example:lib", "", ecosystem="maven", manifest="pom.xml"),
            ),
            provider,
        )

        par_ecosysteme = {item.ecosystem: item for item in result.ecosystems}
        assert par_ecosysteme["npm"].verified == 1
        # L'ecart entre `total` et `verified` est la zone d'ombre, et c'est
        # elle qu'il faut pouvoir afficher.
        assert par_ecosysteme["maven"].total == 1
        assert par_ecosysteme["maven"].verified == 0


# --------------------------------------------------------------------------
# Contrat de la route
# --------------------------------------------------------------------------


class TestRoute:
    def test_la_route_exige_le_jeton(self, client, project):
        uid, _ = project
        response = client.post(
            f"/api/project/{uid}/dependencies",
            json=inventory(record("express", "4.18.2")).model_dump(),
        )
        assert response.status_code == 401

    def test_un_projet_inconnu_repond_404(self, client):
        response = client.post(
            "/api/project/inexistant/dependencies",
            json=inventory().model_dump(),
            headers=auth_headers(),
        )
        assert response.status_code == 404

    def test_un_nom_de_dependance_avec_espace_est_refuse(self, client, project):
        """Une ligne de manifeste transmise a la place d'un nom.

        C'est elle qui pourrait porter `--index-url https://user:mdp@…`.
        """
        uid, _ = project
        response = client.post(
            f"/api/project/{uid}/dependencies",
            json={
                "dependencies": [
                    {
                        "name": "--index-url https://u:p@depot.example/simple",
                        "ecosystem": "pypi",
                        "version": "",
                        "direct": True,
                        "manifest": "requirements.txt",
                        "source": "manifest",
                    }
                ],
                "manifests_read": 1,
                "truncated": False,
                "warnings": [],
                "inventory_version": "1.0.0",
                "check_vulnerabilities": False,
            },
            headers=auth_headers(),
        )
        assert response.status_code == 422

    def test_le_contexte_de_projet_porte_les_compteurs(self, client, project):
        uid, _ = project

        client.post(
            f"/api/project/{uid}/dependencies",
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
                "check_vulnerabilities": False,
            },
            headers=auth_headers(),
        )

        contexte = client.get(
            f"/api/project/{uid}/context", headers=auth_headers()
        ).json()

        assert contexte["dependency_statistics"]["total"] == 1
        assert contexte["dependency_ecosystems"][0]["ecosystem"] == "npm"
        # L'etat du fournisseur voyage avec les chiffres : sans lui, un
        # total nul se lirait comme un feu vert.
        assert contexte["vulnerability_statistics"]["conclusive"] is False
        assert contexte["vulnerability_statistics"]["provider_status"] == "disabled"

    def test_la_capacite_desactivee_repond_503(self, client, project, monkeypatch):
        uid, _ = project
        monkeypatch.setattr(settings, "dependency_inventory_enabled", False)

        response = client.post(
            f"/api/project/{uid}/dependencies",
            json=inventory().model_dump(),
            headers=auth_headers(),
        )
        assert response.status_code == 503

    def test_l_etat_du_moteur_annonce_ses_capacites(self, client):
        response = client.get("/api/security/health", headers=auth_headers())

        assert response.status_code == 200
        payload = response.json()
        assert payload["secret_detection_enabled"] is True
        assert payload["dependency_inventory_enabled"] is True
        # Constat verifie par ailleurs sur le code source lui-meme.
        assert payload["requires_wazuh"] is False

    def test_l_etat_du_moteur_exige_le_jeton(self, client):
        """Contrairement a /api/code/health, qui sert au diagnostic."""
        assert client.get("/api/security/health").status_code == 401
