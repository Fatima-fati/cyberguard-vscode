"""Tests de la couche de presentation francaise (`app.i18n`).

Deux garanties a tenir :

1. ce que voit l'utilisateur est en francais ;
2. ce qui sert au diagnostic (donnees Wazuh, identifiants techniques)
   n'est jamais reecrit.
"""

import pytest

from app import i18n
from app.ai.schemas import AIAlertAnalysis, AINotification, AuditEntry
from app.models import Agent, Alert, MonitoringStatus

from tests.conftest import make_alert


# --------------------------------------------------------------------------
# Traduction des descriptions Wazuh
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("original", "expected"),
    [
        ("sshd: authentication failed.", "sshd : Échec d'authentification."),
        (
            "Authentication failure for user root",
            "Échec d'authentification pour l'utilisateur root",
        ),
        (
            "Multiple authentication failures detected",
            "Plusieurs échecs d'authentification ont été détectés",
        ),
        ("Wazuh agent disconnected", "L'agent Wazuh s'est déconnecté"),
        (
            "PAM: Multiple failed logins in a small period of time.",
            "PAM : Plusieurs échecs de connexion en peu de temps.",
        ),
        (
            "Attempt to login using a non-existent user",
            "Tentative de connexion avec un utilisateur inexistant",
        ),
        ("Windows Logon Success", "Ouverture de session réussie"),
    ],
)
def test_les_descriptions_wazuh_courantes_sont_traduites(original, expected):
    assert i18n.localize_security_text(original) == expected


def test_les_termes_de_securite_reconnus_restent_en_anglais():
    """SQL injection, XSS, brute force... sont des noms propres du domaine."""
    assert i18n.localize_security_text("SQL injection attempt") == (
        "Tentative de SQL injection"
    )
    assert "brute force" in i18n.localize_security_text(
        "sshd: brute force trying to get access to the system."
    )
    assert "XSS (Cross Site Scripting)" in i18n.localize_security_text(
        "XSS (Cross Site Scripting) attempt"
    )


def test_les_identifiants_techniques_ne_sont_jamais_traduits():
    """IP, chemins, CVE, valeurs citees : recopies a l'identique."""
    text = i18n.localize_security_text(
        "User authentication failure from 192.168.110.134 in file "
        "'/var/log/auth.log' for CVE-2024-1234"
    )

    assert "192.168.110.134" in text
    assert "'/var/log/auth.log'" in text
    assert "CVE-2024-1234" in text


def test_un_texte_deja_francais_n_est_pas_retouche():
    assert i18n.localize_security_text("Tentative SSH sur le serveur") == (
        "Tentative SSH sur le serveur"
    )


def test_un_texte_vide_reste_vide():
    assert i18n.localize_security_text(None) == ""
    assert i18n.localize_security_text("") == ""
    assert i18n.localize_security_text("   ") == ""


def test_translate_alert_message_est_un_alias():
    assert i18n.translate_alert_message is i18n.localize_security_text


# --------------------------------------------------------------------------
# Referentiels
# --------------------------------------------------------------------------


def test_les_severites_ont_un_libelle_francais():
    assert i18n.severity_label("LOW") == "FAIBLE"
    assert i18n.severity_label("MEDIUM") == "MOYENNE"
    assert i18n.severity_label("HIGH") == "ÉLEVÉE"
    assert i18n.severity_label("CRITICAL") == "CRITIQUE"


def test_les_statuts_wazuh_ont_un_libelle_francais():
    assert i18n.agent_status_label("active") == "ACTIVE"
    assert i18n.agent_status_label("disconnected") == "DÉCONNECTÉ"
    assert i18n.agent_status_label("pending") == "EN ATTENTE"
    assert i18n.agent_status_label(None) == "INCONNU"


def test_les_statuts_de_notification_ont_un_libelle_francais():
    """`status` decrit la lecture par l'utilisateur, pas l'analyse IA."""
    assert i18n.notification_status_label("new") == "Nouvelle"
    assert i18n.notification_status_label("acknowledged") == "Vue"
    assert i18n.notification_status_label("dismissed") == "Ignorée"
    assert i18n.notification_status_label("resolved") == "Résolue"


def test_les_etats_d_analyse_ont_un_libelle_francais():
    assert i18n.analysis_status_label("pending") == "En attente d'analyse"
    assert i18n.analysis_status_label("analyzing") == "Analyse en cours"
    assert i18n.analysis_status_label("analyzed") == "Analysée"
    assert i18n.analysis_status_label("failed") == "Échec de l'analyse"
    # Valeur absente : une notification est en attente par defaut.
    assert i18n.analysis_status_label(None) == "En attente d'analyse"


def test_une_classification_inconnue_reste_lisible():
    assert i18n.classification_label("unknown") == "Non déterminé"
    assert i18n.classification_label("brute_force") == "Attaque par brute force"
    # Valeur hors referentiel : traduite au mieux, jamais affichee en snake_case.
    assert "_" not in i18n.classification_label("data_exfiltration")


# --------------------------------------------------------------------------
# Les modeles exposent les libelles sans perdre la donnee technique
# --------------------------------------------------------------------------


def test_l_alerte_expose_la_description_francaise_et_l_originale():
    alert = make_alert("a-1", description="sshd: authentication failed.")

    payload = alert.model_dump()

    # Donnee Wazuh d'origine : intacte.
    assert payload["rule"]["description"] == "sshd: authentication failed."
    assert payload["rule"]["id"] == "5710"
    assert payload["full_log"] == "log de a-1"
    # Version destinee a l'interface.
    assert payload["rule"]["description_fr"] == "sshd : Échec d'authentification."


def test_l_agent_expose_son_statut_brut_et_son_libelle():
    payload = Agent(id="002", name="srv-linux", status="disconnected").model_dump()

    assert payload["status"] == "disconnected"
    assert payload["status_label"] == "DÉCONNECTÉ"


def test_l_etat_de_surveillance_a_un_libelle():
    assert MonitoringStatus(running=True).model_dump()["state_label"] == "EN COURS"
    assert MonitoringStatus(running=False).model_dump()["state_label"] == "ARRÊTÉE"


def test_l_analyse_ia_expose_les_libelles_francais():
    payload = AIAlertAnalysis(
        alert_id="a-1",
        severity="HIGH",
        classification="brute_force",
        threat_type="brute force attack",
        remediation_type="code_patch",
    ).model_dump()

    # Valeurs internes : inchangees, la logique metier s'en sert.
    assert payload["severity"] == "HIGH"
    assert payload["classification"] == "brute_force"
    # Libelles ajoutes pour l'interface.
    assert payload["severity_label"] == "ÉLEVÉE"
    assert payload["classification_label"] == "Attaque par brute force"
    assert payload["remediation_type_label"] == "Correction de code"


def test_la_notification_expose_les_libelles_francais():
    payload = AINotification(
        id=1,
        alert_id="a-1",
        severity="CRITICAL",
        classification="authentication_failure",
        status="new",
        remediation_status="awaiting_confirmation",
        source="wazuh",
    ).model_dump()

    assert payload["status"] == "new"
    assert payload["severity_label"] == "CRITIQUE"
    assert payload["classification_label"] == "Échec d'authentification"
    assert payload["status_label"] == "Nouvelle"
    assert payload["remediation_status_label"] == "En attente de confirmation"
    assert payload["source_label"] == "Niveau Wazuh"


def test_le_journal_d_audit_est_lisible():
    payload = AuditEntry(id=1, action="REMEDIATION_APPLIED").model_dump()

    assert payload["action"] == "REMEDIATION_APPLIED"
    assert payload["action_label"] == "Correction appliquée"


def test_une_alerte_windows_est_aussi_traduite():
    """Aucun systeme n'est privilegie : Linux et Windows suivent la meme voie."""
    alert = Alert.from_hit(
        {
            "_id": "win-1",
            "_source": {
                "timestamp": "2026-08-12T10:00:00.000+0000",
                "agent": {"id": "003", "name": "srv-win"},
                "rule": {
                    "id": 60122,
                    "level": 10,
                    "description": "Windows: Logon Failure - Unknown user or bad password",
                    "groups": ["authentication_failed", "windows"],
                },
                "full_log": "An account failed to log on.",
                "location": "EventChannel",
            },
        }
    )

    assert alert.description_fr.startswith("Windows : Échec d'ouverture de session")
    # Les groupes connus sont traduits, les identifiants Wazuh inconnus restent.
    assert alert.rule.groups_label == "échec d'authentification, windows"
