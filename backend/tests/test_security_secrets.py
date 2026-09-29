"""Tests de la reception et de la persistance des balayages de secrets.

La garantie centrale de ce fichier, celle dont tout le reste depend :
**aucune valeur de secret n'est jamais ecrite en base, ni journalisee.**
Elle est verifiee de deux facons complementaires :

- en **boite noire**, en postant une valeur en clair sur la route et en
  relisant le fichier SQLite lui-meme ;
- en **boite blanche**, en verifiant que le validateur du modele expurge
  meme quand l'appelant ne l'a pas fait.

La seconde compte autant que la premiere : le backend ecoute en local, et
tout processus de la machine peut poster sur ses routes. Faire reposer la
garantie sur la discipline du client serait la faire reposer sur rien.
"""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import store
from app.config import settings
from app.main import app
from app.security import secret_catalog
from app.security.redaction import MASK, looks_redacted, redact_evidence
from app.security.schemas import SecretFindingSubmission, SecurityFinding
from app.security.secrets import apply_confidence
from tests.conftest import auth_headers

# Valeurs FABRIQUEES. Aucune n'est une cle reelle : elles en respectent la
# forme (prefixe, longueur, alphabet) et rien d'autre.
OPENAI_KEY = "sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
GITHUB_TOKEN = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
AWS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
JWT_SECRET = "zK7pQ2mR9xL4vB8nT3wY6cF1hJ5dG0sA"


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def project_uid(client) -> str:
    """Projet enregistre et indexe, prêt a recevoir un balayage."""
    response = client.post(
        "/api/project/discover",
        json={"root_hash": "a" * 64, "project_name": "demo"},
        headers=auth_headers(),
    )
    assert response.status_code == 200
    uid = response.json()["project_uid"]

    client.post(
        f"/api/project/{uid}/index",
        json={
            "files": [{"path": "backend/config.py", "size": 100}],
            "manifests": [],
            "git": {"detected": False},
            "discovered_count": 1,
        },
        headers=auth_headers(),
    )
    return uid


def submission(**overrides) -> dict:
    finding = {
        "rule_id": "secret.openai_api_key",
        "file_path": "backend/config.py",
        "line": 24,
        "column": 12,
        "secret_type": "openai_api_key",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "evidence_redacted": f"OpenAI API key detected: sk-proj-{MASK}",
    }
    finding.update(overrides)
    return {
        "findings": [finding],
        "scanned_files": 42,
        "skipped_files": 3,
        "engine": "secret-scanner",
        "engine_version": "1.0.0",
        "truncated": False,
        "warnings": [],
    }


# --------------------------------------------------------------------------
# Expurgation
# --------------------------------------------------------------------------


class TestExpurgation:
    """Ce que le backend accepte d'ecrire, et ce qu'il refuse."""

    @pytest.mark.parametrize(
        "value",
        [
            OPENAI_KEY,
            GITHUB_TOKEN,
            AWS_KEY_ID,
            JWT_SECRET,
            "xoxb-123456789012-345678901234-A1b2C3d4E5f6G7h8I9j0K1l2",
            "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q",
            "glpat-A1b2C3d4E5f6G7h8I9j0",
        ],
    )
    def test_aucune_valeur_ne_survit_a_l_expurgation(self, value):
        expurge = redact_evidence(f"Secret detected: {value}")

        assert value not in expurge
        assert looks_redacted(expurge)

    def test_l_expurgation_est_idempotente(self):
        """Reappliquer l'expurgation ne degrade pas une preuve deja propre.

        Sans cette propriete, une preuve relue puis reecrite perdrait un
        peu de sa lisibilite a chaque passage, jusqu'a ne plus rien dire.
        """
        once = redact_evidence(f"OpenAI API key detected: {OPENAI_KEY}")
        assert redact_evidence(once) == once

    def test_les_mots_ne_sont_pas_masques(self):
        """Une preuve doit rester lisible : masquer la prose ne protege rien."""
        phrase = "Identifiants de base de donnees dans une chaine de connexion"
        assert redact_evidence(phrase) == phrase

    def test_le_nom_d_une_variable_reste_lisible(self):
        preuve = redact_evidence("Variable AWS_SECRET_ACCESS_KEY declaree en dur")
        assert "AWS_SECRET_ACCESS_KEY" in preuve

    def test_le_validateur_expurge_meme_sans_cooperation_du_client(self):
        """Le modele ne fait aucune confiance a l'appelant.

        Un client d'une version anterieure, une extension modifiee ou un
        appel direct sur la route produiraient une preuve en clair. Le
        validateur la reprend avant qu'elle n'atteigne quoi que ce soit.
        """
        entree = SecretFindingSubmission(
            file_path="backend/config.py",
            line=1,
            secret_type="openai_api_key",
            # En clair, volontairement.
            evidence_redacted=f"key = {OPENAI_KEY}",
        )

        assert OPENAI_KEY not in entree.evidence_redacted
        assert looks_redacted(entree.evidence_redacted)

    def test_le_finding_expurge_sa_preuve_a_la_construction(self):
        finding = SecurityFinding(
            id="x",
            project_uid="p",
            category="SECRET",
            evidence=f"token {GITHUB_TOKEN}",
        )
        assert GITHUB_TOKEN not in finding.evidence


# --------------------------------------------------------------------------
# Rien n'est persiste ni journalise
# --------------------------------------------------------------------------


class TestAucuneValeurPersistee:
    def test_une_valeur_en_clair_postee_n_atteint_jamais_la_base(
        self, client, project_uid, temp_db
    ):
        """Le test le plus important du fichier.

        On poste deliberement une preuve NON expurgee, puis on inspecte le
        fichier SQLite ligne par ligne. La garantie ne porte donc pas sur
        ce que l'API repond, mais sur ce qui est reellement ecrit.
        """
        response = client.post(
            f"/api/project/{project_uid}/secrets",
            json=submission(evidence_redacted=f"OPENAI_API_KEY = {OPENAI_KEY}"),
            headers=auth_headers(),
        )
        assert response.status_code == 200

        connection = sqlite3.connect(str(temp_db))
        contenu = " ".join(
            str(cell)
            for row in connection.execute("SELECT * FROM security_findings")
            for cell in row
        )
        connection.close()

        assert OPENAI_KEY not in contenu
        # Deux marques d'expurgation possibles selon le motif qui a mordu :
        # `[REDACTED]` quand la forme « cle = valeur » a ete reconnue (le
        # nom du champ est alors conserve, ce qui est l'information utile),
        # `********` quand seul le balayage generique s'est applique.
        assert MASK in contenu or "[REDACTED]" in contenu

    def test_la_valeur_n_apparait_dans_aucune_ligne_de_journal(
        self, client, project_uid, caplog
    ):
        with caplog.at_level("DEBUG"):
            client.post(
                f"/api/project/{project_uid}/secrets",
                json=submission(evidence_redacted=f"key = {OPENAI_KEY}"),
                headers=auth_headers(),
            )

        assert OPENAI_KEY not in caplog.text

    def test_la_reponse_ne_renvoie_jamais_la_valeur(self, client, project_uid):
        response = client.post(
            f"/api/project/{project_uid}/secrets",
            json=submission(evidence_redacted=f"key = {OPENAI_KEY}"),
            headers=auth_headers(),
        )

        assert OPENAI_KEY not in response.text

    def test_le_contexte_de_projet_ne_porte_que_des_nombres(
        self, client, project_uid
    ):
        client.post(
            f"/api/project/{project_uid}/secrets",
            json=submission(evidence_redacted=f"key = {OPENAI_KEY}"),
            headers=auth_headers(),
        )

        contexte = client.get(
            f"/api/project/{project_uid}/context", headers=auth_headers()
        ).json()

        assert contexte["secret_statistics"]["total"] == 1
        assert contexte["secret_statistics"]["critical"] == 1
        assert contexte["secret_statistics"]["files_with_secrets"] == 1
        # Aucun chemin, aucune preuve, aucune valeur : le contexte est un
        # resume, le detail vit dans les findings.
        assert OPENAI_KEY not in str(contexte)
        assert "backend/config.py" not in str(contexte["secret_statistics"])


# --------------------------------------------------------------------------
# Gravite et confiance
# --------------------------------------------------------------------------


class TestConfiance:
    @pytest.mark.parametrize(
        "severite,confiance,attendu",
        [
            ("CRITICAL", "HIGH", "CRITICAL"),
            ("CRITICAL", "MEDIUM", "HIGH"),
            # La regle qui protege la credibilite du signal : une liste de
            # critiques ou un sur deux est faux cesse d'etre lue.
            ("CRITICAL", "LOW", "MEDIUM"),
            ("HIGH", "LOW", "MEDIUM"),
            ("MEDIUM", "LOW", "MEDIUM"),
            ("LOW", "LOW", "LOW"),
            ("MEDIUM", "HIGH", "MEDIUM"),
        ],
    )
    def test_la_gravite_est_plafonnee_par_la_confiance(
        self, severite, confiance, attendu
    ):
        assert apply_confidence(severite, confiance) == attendu

    def test_une_detection_douteuse_n_apparait_jamais_en_critical(
        self, client, project_uid
    ):
        response = client.post(
            f"/api/project/{project_uid}/secrets",
            json=submission(confidence="LOW"),
            headers=auth_headers(),
        )

        finding = response.json()["findings"][0]
        assert finding["severity"] != "CRITICAL"
        # La confiance reelle reste visible a cote : l'information n'est
        # pas perdue, elle est simplement affichee pour ce qu'elle est.
        assert finding["confidence"] == "LOW"


# --------------------------------------------------------------------------
# Vocabulaire
# --------------------------------------------------------------------------


class TestCatalogue:
    def test_chaque_type_reconnu_porte_un_titre_et_une_remediation(self):
        for secret_type in secret_catalog.known_types():
            described = secret_catalog.describe(secret_type)
            assert described.title
            assert described.description
            assert described.remediation

    def test_un_type_inconnu_produit_un_message_prudent_plutot_qu_un_silence(self):
        """Taire un secret parce qu'on ne sait pas le nommer serait pire."""
        described = secret_catalog.describe("fournisseur-inexistant")
        assert described.title
        assert "ressemble" in described.description

    def test_la_remediation_demande_de_revoquer_avant_de_retirer(self):
        """L'ordre des deux gestes n'est pas indifferent.

        Retirer la cle du code sans la revoquer ne protege de rien : elle
        reste dans l'historique Git et sur les postes qui ont clone le
        depot.
        """
        remediation = secret_catalog.describe("openai_api_key").remediation
        assert "évoquez" in remediation
        assert remediation.index("évoquez") < remediation.index("retirez")

    def test_le_backend_redige_le_libelle_quand_le_client_se_tait(
        self, client, project_uid
    ):
        """Une extension d'une version anterieure produit un message correct."""
        response = client.post(
            f"/api/project/{project_uid}/secrets",
            json=submission(title="", description="", remediation=""),
            headers=auth_headers(),
        )

        finding = response.json()["findings"][0]
        assert finding["title"] == secret_catalog.describe("openai_api_key").title
        assert finding["remediation"]


# --------------------------------------------------------------------------
# Cycle de vie des findings
# --------------------------------------------------------------------------


class TestCycleDeVie:
    def test_un_second_balayage_ne_cree_pas_de_doublon(self, client, project_uid):
        for _ in range(3):
            response = client.post(
                f"/api/project/{project_uid}/secrets",
                json=submission(),
                headers=auth_headers(),
            )

        assert len(response.json()["findings"]) == 1
        assert response.json()["statistics"]["total"] == 1

    def test_un_secret_corrige_disparait_du_balayage_suivant(
        self, client, project_uid
    ):
        client.post(
            f"/api/project/{project_uid}/secrets",
            json=submission(),
            headers=auth_headers(),
        )

        vide = dict(submission())
        vide["findings"] = []
        response = client.post(
            f"/api/project/{project_uid}/secrets",
            json=vide,
            headers=auth_headers(),
        )

        # Le laisser affiche serait faux : le probleme n'existe plus.
        assert response.json()["findings"] == []
        assert response.json()["statistics"]["total"] == 0

    def test_deux_projets_ne_melangent_jamais_leurs_findings(self, client):
        """Deux projets partageant `config.py` doivent rester etanches."""
        uids = []
        for index, empreinte in enumerate(("a" * 64, "b" * 64)):
            registration = client.post(
                "/api/project/discover",
                json={"root_hash": empreinte, "project_name": f"p{index}"},
                headers=auth_headers(),
            ).json()
            uids.append(registration["project_uid"])

        client.post(
            f"/api/project/{uids[0]}/secrets",
            json=submission(secret_type="openai_api_key"),
            headers=auth_headers(),
        )
        client.post(
            f"/api/project/{uids[1]}/secrets",
            json=submission(secret_type="github_token"),
            headers=auth_headers(),
        )

        premier = client.get(
            f"/api/project/{uids[0]}/findings", headers=auth_headers()
        ).json()
        second = client.get(
            f"/api/project/{uids[1]}/findings", headers=auth_headers()
        ).json()

        assert len(premier) == 1
        assert len(second) == 1
        assert premier[0]["id"] != second[0]["id"]
        assert premier[0]["project_uid"] == uids[0]
        assert second[0]["project_uid"] == uids[1]

    def test_le_plafond_serveur_est_applique_et_annonce(
        self, client, project_uid, monkeypatch
    ):
        """Le backend ne fait pas confiance a la borne du client."""
        monkeypatch.setattr(settings, "secret_max_findings", 2)

        lot = dict(submission())
        lot["findings"] = [
            {
                "rule_id": "secret.generic_api_key",
                "file_path": f"src/f{index}.py",
                "line": 1,
                "secret_type": "generic_api_key",
                "severity": "HIGH",
                "confidence": "HIGH",
                "evidence_redacted": f"API key detected: abcd{MASK}",
            }
            for index in range(10)
        ]

        response = client.post(
            f"/api/project/{project_uid}/secrets",
            json=lot,
            headers=auth_headers(),
        )

        payload = response.json()
        assert payload["statistics"]["total"] == 2
        # Une couverture partielle se dit : un decompte plafonne presente
        # comme complet serait un mensonge de securite.
        assert payload["statistics"]["truncated"] is True
        assert any("tronque" in warning for warning in payload["warnings"])


# --------------------------------------------------------------------------
# Contrat de la route
# --------------------------------------------------------------------------


class TestRoute:
    def test_la_route_exige_le_jeton(self, client, project_uid):
        response = client.post(
            f"/api/project/{project_uid}/secrets", json=submission()
        )
        assert response.status_code == 401

    def test_un_projet_inconnu_repond_404_avec_la_marche_a_suivre(self, client):
        response = client.post(
            "/api/project/inexistant/secrets",
            json=submission(),
            headers=auth_headers(),
        )

        assert response.status_code == 404
        assert "discover" in str(response.json()["detail"])

    def test_un_chemin_absolu_est_refuse(self, client, project_uid):
        response = client.post(
            f"/api/project/{project_uid}/secrets",
            json=submission(file_path="C:/Users/moi/projet/config.py"),
            headers=auth_headers(),
        )
        assert response.status_code == 422

    def test_une_remontee_d_arborescence_est_refusee(self, client, project_uid):
        response = client.post(
            f"/api/project/{project_uid}/secrets",
            json=submission(file_path="../../etc/passwd"),
            headers=auth_headers(),
        )
        assert response.status_code == 422

    def test_la_capacite_desactivee_repond_503_et_non_une_liste_vide(
        self, client, project_uid, monkeypatch
    ):
        """Une liste vide se lirait « rien a signaler ». Ce n'est pas le cas."""
        monkeypatch.setattr(settings, "secret_detection_enabled", False)

        response = client.post(
            f"/api/project/{project_uid}/secrets",
            json=submission(),
            headers=auth_headers(),
        )

        assert response.status_code == 503
        assert "desactive" in str(response.json()["detail"]).lower()

    def test_le_balayage_alimente_la_liste_unifiee_des_findings(
        self, client, project_uid
    ):
        client.post(
            f"/api/project/{project_uid}/secrets",
            json=submission(),
            headers=auth_headers(),
        )

        findings = client.get(
            f"/api/project/{project_uid}/findings?category=SECRET",
            headers=auth_headers(),
        ).json()

        assert len(findings) == 1
        assert findings[0]["category"] == "SECRET"
        assert findings[0]["detection_engine"] == "secret-scanner"
        assert findings[0]["file"] == "backend/config.py"
        assert findings[0]["line_start"] == 24


# --------------------------------------------------------------------------
# Persistance
# --------------------------------------------------------------------------


class TestPersistance:
    def test_une_decision_de_l_utilisateur_survit_a_un_nouveau_balayage(self):
        """Un faux positif ecarte ne doit pas reapparaitre.

        C'est le plus sur moyen de rendre un outil de securite
        inutilisable : si chaque balayage ramene ce que l'utilisateur a
        deja traite, il cesse de le lire.
        """
        rows = [
            {
                "finding_id": "f1",
                "fingerprint": "empreinte-1",
                "title": "Secret",
                "severity": "CRITICAL",
            }
        ]
        store.sync_security_findings("p1", "SECRET", rows)

        with store.get_connection() as connection:
            connection.execute(
                "UPDATE security_findings SET status = 'dismissed' "
                "WHERE finding_id = 'f1'"
            )

        store.sync_security_findings("p1", "SECRET", rows)

        enregistre = store.get_security_finding("f1")
        assert enregistre is not None
        assert enregistre["status"] == "dismissed"

    def test_un_finding_disparu_du_balayage_est_supprime(self):
        store.sync_security_findings(
            "p1",
            "SECRET",
            [{"finding_id": "f1", "fingerprint": "e1"}, {"finding_id": "f2", "fingerprint": "e2"}],
        )
        resultat = store.sync_security_findings(
            "p1", "SECRET", [{"finding_id": "f1", "fingerprint": "e1"}]
        )

        assert resultat["removed"] == 1
        assert store.get_security_finding("f2") is None

    def test_les_categories_sont_synchronisees_independamment(self):
        """Un balayage de secrets ne doit pas effacer les dependances."""
        store.sync_security_findings(
            "p1", "SECRET", [{"finding_id": "s1", "fingerprint": "e1"}]
        )
        store.sync_security_findings(
            "p1", "DEPENDENCY", [{"finding_id": "d1", "fingerprint": "e2"}]
        )
        store.sync_security_findings(
            "p1", "SECRET", [{"finding_id": "s2", "fingerprint": "e3"}]
        )

        identifiants = {
            row["finding_id"] for row in store.list_security_findings("p1")
        }
        assert identifiants == {"s2", "d1"}
