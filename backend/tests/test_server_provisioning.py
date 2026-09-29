"""Tests de l'ajout d'un serveur (instructions + verification).

Aucun appel a un Wazuh reel : la liste des agents est simulee.
"""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import server_provisioning
from app.config import settings
from app.main import app
from app.models import Agent, ServerCheckRequest, ServerProvisionRequest
from app.server_provisioning import (
    MANAGER_AGENT_ID,
    ProvisioningConfigError,
    build_instructions,
    check_server,
    exclude_manager,
    find_matching_agents,
    validate_enrollment_config,
)
from app.wazuh_client import WazuhUnavailableError

MANAGER = Agent(
    id="000", name="wazuh.manager", ip="127.0.0.1", status="active", os="Amazon Linux"
)
WEB = Agent(
    id="001", name="web-server-01", ip="192.168.1.50", status="active", os="Ubuntu 22.04"
)
DB = Agent(
    id="002", name="db-server-01", ip="192.168.1.51", status="disconnected", os="Debian 12"
)


class FakeAgentsClient:
    """Client Wazuh simule : ne sert que la liste des agents."""

    def __init__(self, agents=None, error=None):
        self.agents = agents if agents is not None else []
        self.error = error
        self.calls = 0

    async def get_agents(self, limit=None):
        self.calls += 1
        if self.error:
            raise self.error
        return list(self.agents)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def enrollment_config(monkeypatch):
    """Configuration d'enrolement valide et stable pour tous les tests.

    Les tests ne dependent donc pas du backend/.env de la machine : chacun
    surcharge ensuite ce qu'il veut verifier.
    """
    monkeypatch.setattr(settings, "wazuh_manager_address", "wazuh.test.local")
    monkeypatch.setattr(settings, "wazuh_enrollment_port", 1515)
    monkeypatch.setattr(settings, "wazuh_agent_port", 1514)
    monkeypatch.setattr(settings, "wazuh_agent_version", "4.14.6")
    monkeypatch.setattr(
        settings, "wazuh_packages_base_url", "https://packages.wazuh.com/4.x"
    )


def request_for(os_name="linux", **overrides):
    payload = {"name": "web-server-01", "ip": "192.168.1.50", "os": os_name}
    payload.update(overrides)
    return ServerProvisionRequest(**payload)


# --------------------------------------------------------------------------
# Validation du formulaire
# --------------------------------------------------------------------------


def test_le_nom_est_obligatoire():
    with pytest.raises(ValidationError, match="obligatoire"):
        request_for(name="   ")


def test_le_nom_refuse_les_caracteres_interdits_par_wazuh():
    # Wazuh rejette les espaces dans un nom d'agent.
    with pytest.raises(ValidationError, match="lettres, chiffres"):
        request_for(name="web server 01")


def test_le_nom_est_nettoye():
    assert request_for(name="  web-01  ").name == "web-01"


def test_l_ip_doit_etre_valide():
    with pytest.raises(ValidationError, match="Adresse IP invalide"):
        request_for(ip="999.1.1.1")

    with pytest.raises(ValidationError, match="Adresse IP invalide"):
        request_for(ip="pas-une-ip")


def test_l_ip_accepte_ipv4_et_ipv6():
    assert request_for(ip="10.0.0.8").ip == "10.0.0.8"
    assert request_for(ip="2001:db8::1").ip == "2001:db8::1"


def test_l_os_doit_etre_linux_ou_windows():
    with pytest.raises(ValidationError):
        request_for(os_name="macos")


def test_la_description_est_optionnelle():
    assert request_for().description is None
    assert request_for(description="  Serveur web  ").description == "Serveur web"
    assert request_for(description="   ").description is None


# --------------------------------------------------------------------------
# Generation des instructions
# --------------------------------------------------------------------------


def test_instructions_linux():
    result = build_instructions(request_for("linux"))
    commands = "\n".join(result.commands)

    assert result.server.os == "linux"
    assert result.enrollment_port == settings.wazuh_enrollment_port
    assert result.agent_version == settings.wazuh_agent_version

    # Les 6 etapes demandees sont couvertes.
    assert "wazuh-agent" in commands
    assert f"WAZUH_MANAGER='{result.manager_address}'" in commands
    assert "WAZUH_REGISTRATION_SERVER=" in commands
    assert "WAZUH_AGENT_NAME='web-server-01'" in commands
    assert "systemctl enable wazuh-agent" in commands
    assert "systemctl start wazuh-agent" in commands
    assert any("systemctl status" in cmd for cmd in result.verify_commands)

    # Rien de specifique a Windows.
    assert "msiexec" not in commands
    assert "PowerShell" not in commands


def test_instructions_windows():
    result = build_instructions(request_for("windows"))
    commands = "\n".join(result.commands)

    assert result.server.os == "windows"
    assert "Invoke-WebRequest" in commands
    assert ".msi" in commands
    assert "msiexec.exe" in commands
    assert f"WAZUH_MANAGER='{result.manager_address}'" in commands
    assert "WAZUH_AGENT_NAME='web-server-01'" in commands
    assert "NET START WazuhSvc" in commands
    assert any("Get-Service" in cmd for cmd in result.verify_commands)

    # Rien de specifique a Linux.
    assert "systemctl" not in commands
    assert "dpkg" not in commands


def test_la_version_et_le_depot_viennent_de_la_configuration(monkeypatch):
    monkeypatch.setattr(settings, "wazuh_agent_version", "9.9.9")
    monkeypatch.setattr(settings, "wazuh_packages_base_url", "https://depot.test/4.x")

    commands = "\n".join(build_instructions(request_for("linux")).commands)

    assert "9.9.9" in commands
    assert "https://depot.test/4.x" in commands


def test_l_adresse_du_manager_vient_de_la_configuration(monkeypatch):
    monkeypatch.setattr(settings, "wazuh_manager_address", "wazuh.exemple.fr")

    result = build_instructions(request_for("linux"))

    assert result.manager_address == "wazuh.exemple.fr"
    assert "wazuh.exemple.fr" in "\n".join(result.commands)


def test_une_adresse_de_bouclage_est_signalee(monkeypatch):
    """127.0.0.1 est refuse : un serveur distant ne peut pas s'y enroler."""
    monkeypatch.setattr(settings, "wazuh_manager_address", "127.0.0.1")

    with pytest.raises(ProvisioningConfigError) as erreur:
        build_instructions(request_for("linux"))

    assert "WAZUH_MANAGER_ADDRESS" in erreur.value.message


def test_aucune_execution_distante_dans_les_instructions():
    """L'application ne doit jamais proposer d'agir a distance."""
    for os_name in ("linux", "windows"):
        result = build_instructions(request_for(os_name))
        blob = " ".join(result.commands + result.verify_commands).lower()

        for interdit in ("ssh ", "scp ", "sshpass", "psexec", "winrm", "invoke-command"):
            assert interdit not in blob, f"{interdit} present dans les commandes {os_name}"


def test_aucun_credential_dans_les_instructions():
    for os_name in ("linux", "windows"):
        result = build_instructions(request_for(os_name))
        blob = result.model_dump_json().lower()

        assert settings.wazuh_api_password.lower() not in blob
        assert settings.indexer_password.lower() not in blob
        assert settings.wazuh_api_user.lower() not in blob
        assert "password" not in blob
        assert "authorization" not in blob
        assert "bearer" not in blob


# --------------------------------------------------------------------------
# Configuration d'enrolement (WAZUH_MANAGER_ADDRESS et compagnie)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "adresse",
    ["192.168.11.144", "wazuh-manager.company.local", "10.20.30.10"],
)
@pytest.mark.parametrize("os_name", ["linux", "windows"])
def test_l_adresse_configuree_est_celle_utilisee(monkeypatch, adresse, os_name):
    """Local, entreprise ou datacenter : le .env fait foi, sans exception."""
    monkeypatch.setattr(settings, "wazuh_manager_address", adresse)

    result = build_instructions(request_for(os_name))
    commands = "\n".join(result.commands)

    assert result.manager_address == adresse
    assert f"WAZUH_MANAGER='{adresse}'" in commands
    assert f"WAZUH_REGISTRATION_SERVER='{adresse}'" in commands
    assert adresse in "\n".join(result.notes)


def test_l_adresse_du_manager_est_nettoyee(monkeypatch):
    monkeypatch.setattr(settings, "wazuh_manager_address", "  10.20.30.10  ")

    assert build_instructions(request_for("linux")).manager_address == "10.20.30.10"


@pytest.mark.parametrize("os_name", ["linux", "windows"])
def test_sans_adresse_de_manager_la_generation_echoue(monkeypatch, os_name):
    monkeypatch.setattr(settings, "wazuh_manager_address", "")

    with pytest.raises(ProvisioningConfigError) as erreur:
        build_instructions(request_for(os_name))

    message = erreur.value.message
    assert "L'adresse du Wazuh Manager n'est pas configurée." in message
    assert "WAZUH_MANAGER_ADDRESS" in message
    assert ".env" in message


def test_l_adresse_n_est_jamais_deduite_de_l_api_url(monkeypatch):
    """Le port 55000 est souvent expose en local : ce n'est pas une adresse
    d'enrolement pour autant."""
    monkeypatch.setattr(settings, "wazuh_manager_address", "")
    monkeypatch.setattr(settings, "wazuh_api_url", "https://127.0.0.1:55000")

    assert settings.manager_address == ""

    with pytest.raises(ProvisioningConfigError):
        build_instructions(request_for("linux"))


@pytest.mark.parametrize("adresse", ["127.0.0.1", "localhost", "::1", "0.0.0.0"])
def test_une_adresse_locale_est_refusee_pour_un_serveur_distant(monkeypatch, adresse):
    monkeypatch.setattr(settings, "wazuh_manager_address", adresse)

    with pytest.raises(ProvisioningConfigError) as erreur:
        build_instructions(request_for("linux", ip="192.168.1.50"))

    assert "WAZUH_MANAGER_ADDRESS" in erreur.value.message


def test_une_adresse_locale_reste_valable_pour_la_machine_du_manager(monkeypatch):
    """Cas legitime : l'agent tourne sur la machine du manager elle-meme."""
    monkeypatch.setattr(settings, "wazuh_manager_address", "127.0.0.1")

    result = build_instructions(request_for("linux", ip="127.0.0.1"))

    assert result.manager_address == "127.0.0.1"


@pytest.mark.parametrize("port", [0, 70000, -1])
def test_un_port_d_enrolement_invalide_est_refuse(monkeypatch, port):
    monkeypatch.setattr(settings, "wazuh_enrollment_port", port)

    with pytest.raises(ProvisioningConfigError) as erreur:
        build_instructions(request_for("linux"))

    assert "WAZUH_ENROLLMENT_PORT" in erreur.value.message


def test_un_port_de_communication_invalide_est_refuse(monkeypatch):
    monkeypatch.setattr(settings, "wazuh_agent_port", 0)

    with pytest.raises(ProvisioningConfigError) as erreur:
        build_instructions(request_for("linux"))

    assert "WAZUH_AGENT_PORT" in erreur.value.message


def test_une_version_absente_est_refusee(monkeypatch):
    monkeypatch.setattr(settings, "wazuh_agent_version", "   ")

    with pytest.raises(ProvisioningConfigError) as erreur:
        build_instructions(request_for("linux"))

    assert "WAZUH_AGENT_VERSION" in erreur.value.message


def test_une_version_fantaisiste_est_refusee(monkeypatch):
    monkeypatch.setattr(settings, "wazuh_agent_version", "derniere; rm -rf /")

    with pytest.raises(ProvisioningConfigError) as erreur:
        build_instructions(request_for("linux"))

    assert "WAZUH_AGENT_VERSION" in erreur.value.message


@pytest.mark.parametrize("url", ["", "   ", "packages.wazuh.com", "ftp://depot/4.x"])
def test_un_depot_invalide_est_refuse(monkeypatch, url):
    monkeypatch.setattr(settings, "wazuh_packages_base_url", url)

    with pytest.raises(ProvisioningConfigError) as erreur:
        build_instructions(request_for("linux"))

    assert "WAZUH_PACKAGES_BASE_URL" in erreur.value.message


def test_la_configuration_valide_est_renvoyee_telle_quelle(monkeypatch):
    monkeypatch.setattr(settings, "wazuh_manager_address", "10.20.30.10")
    monkeypatch.setattr(settings, "wazuh_packages_base_url", "https://depot.test/4.x/")

    config = validate_enrollment_config(target_ip="192.168.1.50")

    assert config.manager == "10.20.30.10"
    assert config.version == "4.14.6"
    # La barre finale est retiree : les URL sont construites par concatenation.
    assert config.base_url == "https://depot.test/4.x"
    assert config.enrollment_port == 1515
    assert config.agent_port == 1514


# --------------------------------------------------------------------------
# Ports, version et nom de paquet : tout vient du .env
# --------------------------------------------------------------------------


@pytest.mark.parametrize("os_name", ["linux", "windows"])
def test_les_ports_viennent_de_la_configuration(monkeypatch, os_name):
    monkeypatch.setattr(settings, "wazuh_enrollment_port", 2515)
    monkeypatch.setattr(settings, "wazuh_agent_port", 2514)

    result = build_instructions(request_for(os_name))
    commands = "\n".join(result.commands)

    assert result.enrollment_port == 2515
    assert result.agent_port == 2514
    assert "WAZUH_REGISTRATION_PORT='2515'" in commands
    assert "WAZUH_MANAGER_PORT='2514'" in commands
    assert "2515/TCP" in "\n".join(result.notes)
    assert "2514/TCP" in "\n".join(result.notes)


@pytest.mark.parametrize("os_name", ["linux", "windows"])
def test_les_ports_par_defaut_sont_1515_et_1514(os_name):
    result = build_instructions(request_for(os_name))
    commands = "\n".join(result.commands)

    assert result.enrollment_port == 1515
    assert result.agent_port == 1514
    assert "WAZUH_REGISTRATION_PORT='1515'" in commands
    assert "WAZUH_MANAGER_PORT='1514'" in commands


def test_le_nom_du_paquet_linux_suit_la_version(monkeypatch):
    monkeypatch.setattr(settings, "wazuh_agent_version", "4.15.2")

    commands = "\n".join(build_instructions(request_for("linux")).commands)

    assert "wazuh-agent_4.15.2-1_amd64.deb" in commands
    assert "wazuh-agent-4.15.2-1.x86_64.rpm" in "\n".join(
        build_instructions(request_for("linux")).notes
    )


def test_le_nom_du_paquet_windows_suit_la_version(monkeypatch):
    monkeypatch.setattr(settings, "wazuh_agent_version", "4.15.2")

    result = build_instructions(request_for("windows"))

    assert "wazuh-agent-4.15.2-1.msi" in "\n".join(result.commands)
    assert result.agent_version == "4.15.2"


def test_une_revision_de_paquet_explicite_est_respectee(monkeypatch):
    """WAZUH_AGENT_VERSION=4.14.6-2 ne doit pas devenir 4.14.6-2-1."""
    monkeypatch.setattr(settings, "wazuh_agent_version", "4.14.6-2")

    commands = "\n".join(build_instructions(request_for("linux")).commands)

    assert "wazuh-agent_4.14.6-2_amd64.deb" in commands
    assert "4.14.6-2-1" not in commands


@pytest.mark.parametrize("os_name", ["linux", "windows"])
def test_aucune_adresse_en_dur_dans_les_instructions(monkeypatch, os_name):
    """Rien qui ressemble a une adresse de developpement ne doit subsister."""
    monkeypatch.setattr(settings, "wazuh_manager_address", "wazuh-manager.company.local")

    blob = build_instructions(request_for(os_name)).model_dump_json()

    for interdit in ("127.0.0.1", "localhost", "192.168.11.144", "0.0.0.0"):
        assert interdit not in blob


# --------------------------------------------------------------------------
# Correspondance des agents
# --------------------------------------------------------------------------


def test_l_agent_000_est_ignore():
    assert exclude_manager([MANAGER, WEB]) == [WEB]

    # Meme si le nom ou l'IP correspondent exactement.
    assert find_matching_agents([MANAGER], name="wazuh.manager") == []
    assert find_matching_agents([MANAGER], name="peu-importe", ip="127.0.0.1") == []
    assert MANAGER.id == MANAGER_AGENT_ID


def test_correspondance_par_nom():
    assert find_matching_agents([MANAGER, WEB, DB], name="web-server-01") == [WEB]


def test_correspondance_par_nom_insensible_a_la_casse():
    assert find_matching_agents([WEB], name="  WEB-Server-01 ") == [WEB]


def test_correspondance_par_ip():
    assert find_matching_agents([MANAGER, WEB, DB], name="autre-nom", ip="192.168.1.51") == [DB]


def test_aucune_correspondance():
    assert find_matching_agents([MANAGER, WEB], name="inconnu", ip="10.9.9.9") == []


def test_plusieurs_correspondances():
    jumeau = Agent(id="003", name="autre", ip="192.168.1.50", status="active")

    matches = find_matching_agents([MANAGER, WEB, jumeau], name="web-server-01", ip="192.168.1.50")

    assert len(matches) == 2
    assert {agent.id for agent in matches} == {"001", "003"}


# --------------------------------------------------------------------------
# Verification aupres du manager
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_agent_trouve():
    status = await check_server(
        FakeAgentsClient([MANAGER, WEB]),
        ServerCheckRequest(name="web-server-01", ip="192.168.1.50"),
    )

    assert status.connected is True
    assert status.status == "connected"
    assert status.message == "Serveur connecté"
    assert status.agent.id == "001"
    assert status.agent.os == "Ubuntu 22.04"
    assert status.agent.status == "active"


@pytest.mark.asyncio
async def test_check_agent_enrole_mais_inactif():
    status = await check_server(
        FakeAgentsClient([MANAGER, DB]), ServerCheckRequest(name="db-server-01")
    )

    assert status.connected is False
    assert status.status == "pending"
    assert "inactif" in status.message
    assert status.agent.id == "002"


@pytest.mark.asyncio
async def test_check_agent_non_trouve_repond_normalement():
    status = await check_server(
        FakeAgentsClient([MANAGER]), ServerCheckRequest(name="web-server-01", ip="192.168.1.50")
    )

    assert status.connected is False
    assert status.status == "pending"
    assert status.message == "Agent non détecté"
    assert status.agent is None


@pytest.mark.asyncio
async def test_check_plusieurs_correspondances():
    jumeau = Agent(id="003", name="autre", ip="192.168.1.50", status="active")

    status = await check_server(
        FakeAgentsClient([MANAGER, WEB, jumeau]),
        ServerCheckRequest(name="web-server-01", ip="192.168.1.50"),
    )

    assert status.connected is False
    assert status.status == "multiple"
    assert len(status.matches) == 2
    assert status.agent is None


@pytest.mark.asyncio
async def test_check_remonte_l_indisponibilite_de_wazuh():
    with pytest.raises(WazuhUnavailableError):
        await check_server(
            FakeAgentsClient(error=WazuhUnavailableError("Wazuh Manager API injoignable")),
            ServerCheckRequest(name="web-server-01"),
        )


# --------------------------------------------------------------------------
# Endpoints HTTP
# --------------------------------------------------------------------------


def test_endpoint_instructions_linux(client):
    response = client.post(
        "/api/servers/provision/instructions",
        json={"name": "web-server-01", "ip": "192.168.1.50", "os": "linux", "description": "Web"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["server"] == {
        "name": "web-server-01",
        "ip": "192.168.1.50",
        "os": "linux",
        "description": "Web",
    }
    assert body["enrollment_port"] == settings.wazuh_enrollment_port
    assert body["instructions"] and body["commands"]


def test_endpoint_instructions_sans_manager_configure(client, monkeypatch):
    """Plutot qu'une commande fausse, une erreur que l'admin peut corriger."""
    monkeypatch.setattr(settings, "wazuh_manager_address", "")

    response = client.post(
        "/api/servers/provision/instructions",
        json={"name": "web-server-01", "ip": "192.168.1.50", "os": "linux"},
    )

    assert response.status_code == 503
    message = response.json()["detail"]["error"]
    assert "L'adresse du Wazuh Manager n'est pas configurée." in message
    assert "WAZUH_MANAGER_ADDRESS" in message
    assert "127.0.0.1" not in response.text


def test_endpoint_instructions_refuse_une_adresse_de_bouclage(client, monkeypatch):
    monkeypatch.setattr(settings, "wazuh_manager_address", "127.0.0.1")

    response = client.post(
        "/api/servers/provision/instructions",
        json={"name": "web-server-01", "ip": "192.168.1.50", "os": "linux"},
    )

    assert response.status_code == 503
    assert "WAZUH_MANAGER_ADDRESS" in response.json()["detail"]["error"]


@pytest.mark.parametrize(
    "adresse",
    ["192.168.11.144", "wazuh-manager.company.local", "10.20.30.10"],
)
@pytest.mark.parametrize("os_name", ["linux", "windows"])
def test_endpoint_instructions_utilise_l_adresse_configuree(
    client, monkeypatch, adresse, os_name
):
    monkeypatch.setattr(settings, "wazuh_manager_address", adresse)

    response = client.post(
        "/api/servers/provision/instructions",
        json={"name": "web-server-01", "ip": "192.168.1.50", "os": os_name},
    )

    assert response.status_code == 200
    body = response.json()
    commands = "\n".join(body["commands"])

    assert body["manager_address"] == adresse
    assert body["enrollment_port"] == 1515
    assert body["agent_port"] == 1514
    assert body["agent_version"] == "4.14.6"
    assert f"WAZUH_MANAGER='{adresse}'" in commands
    assert "127.0.0.1" not in response.text


def test_endpoint_instructions_ne_divulgue_aucun_credential(client, monkeypatch):
    monkeypatch.setattr(settings, "wazuh_api_password", "s3cret-manager")
    monkeypatch.setattr(settings, "indexer_password", "s3cret-indexer")
    monkeypatch.setattr(settings, "openai_api_key", "sk-secret-openai")

    for os_name in ("linux", "windows"):
        text = client.post(
            "/api/servers/provision/instructions",
            json={"name": "web-server-01", "ip": "192.168.1.50", "os": os_name},
        ).text

        assert "s3cret-manager" not in text
        assert "s3cret-indexer" not in text
        assert "sk-secret-openai" not in text
        assert settings.wazuh_api_user not in text
        assert "password" not in text.lower()
        assert "authorization" not in text.lower()
        assert "bearer" not in text.lower()


def test_endpoint_instructions_refuse_une_ip_invalide(client):
    response = client.post(
        "/api/servers/provision/instructions",
        json={"name": "web", "ip": "300.1.1.1", "os": "linux"},
    )

    assert response.status_code == 422


def test_endpoint_instructions_refuse_un_os_inconnu(client):
    response = client.post(
        "/api/servers/provision/instructions",
        json={"name": "web", "ip": "10.0.0.1", "os": "macos"},
    )

    assert response.status_code == 422


def test_endpoint_check_agent_trouve(client, monkeypatch):
    monkeypatch.setattr(
        server_provisioning, "check_server", check_server
    )  # service reel, client simule
    monkeypatch.setattr(
        "app.routes.get_wazuh_client", lambda: FakeAgentsClient([MANAGER, WEB])
    )

    response = client.post(
        "/api/servers/check", json={"name": "web-server-01", "ip": "192.168.1.50"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["connected"] is True
    assert body["status"] == "connected"
    assert body["agent"]["id"] == "001"


def test_endpoint_check_agent_absent_ne_renvoie_pas_500(client, monkeypatch):
    monkeypatch.setattr("app.routes.get_wazuh_client", lambda: FakeAgentsClient([MANAGER]))

    response = client.post("/api/servers/check", json={"name": "inconnu", "ip": "10.0.0.9"})

    assert response.status_code == 200
    body = response.json()
    assert body["connected"] is False
    assert body["status"] == "pending"
    assert body["message"] == "Agent non détecté"


def test_endpoint_check_wazuh_indisponible(client, monkeypatch):
    monkeypatch.setattr(
        "app.routes.get_wazuh_client",
        lambda: FakeAgentsClient(error=WazuhUnavailableError("Wazuh Manager API injoignable")),
    )

    response = client.post("/api/servers/check", json={"name": "web-server-01"})

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert "injoignable" in detail["error"]
    # Aucun secret ni trace technique dans la reponse.
    assert settings.wazuh_api_password not in response.text
    assert "Traceback" not in response.text


def test_endpoint_check_ne_divulgue_aucun_credential(client, monkeypatch):
    monkeypatch.setattr(
        "app.routes.get_wazuh_client", lambda: FakeAgentsClient([MANAGER, WEB])
    )

    text = client.post("/api/servers/check", json={"name": "web-server-01"}).text

    assert settings.wazuh_api_password not in text
    assert settings.indexer_password not in text
    assert "password" not in text.lower()
    assert "bearer" not in text.lower()


# --------------------------------------------------------------------------
# Integration avec la liste de serveurs existante
# --------------------------------------------------------------------------


def test_la_liste_existante_exclut_le_manager(client, monkeypatch):
    monkeypatch.setattr(
        "app.routes.get_wazuh_client", lambda: FakeAgentsClient([MANAGER, WEB, DB])
    )

    body = client.get("/api/servers").json()

    assert [agent["id"] for agent in body] == ["001", "002"]
    assert all(agent["id"] != "000" for agent in body)


def test_la_liste_existante_peut_inclure_le_manager(client, monkeypatch):
    monkeypatch.setattr(
        "app.routes.get_wazuh_client", lambda: FakeAgentsClient([MANAGER, WEB])
    )

    body = client.get("/api/servers?include_manager=true").json()

    assert [agent["id"] for agent in body] == ["000", "001"]


def test_un_serveur_enrole_apparait_dans_la_liste_existante(client, monkeypatch):
    """Pas de seconde liste : l'agent detecte sort de /api/servers."""
    fake = FakeAgentsClient([MANAGER])
    monkeypatch.setattr("app.routes.get_wazuh_client", lambda: fake)

    assert client.get("/api/servers").json() == []

    check = client.post(
        "/api/servers/check", json={"name": "web-server-01", "ip": "192.168.1.50"}
    ).json()
    assert check["status"] == "pending"

    # L'utilisateur installe l'agent : Wazuh l'expose desormais.
    fake.agents = [MANAGER, WEB]

    check = client.post(
        "/api/servers/check", json={"name": "web-server-01", "ip": "192.168.1.50"}
    ).json()
    assert check["connected"] is True

    servers = client.get("/api/servers").json()
    assert [agent["name"] for agent in servers] == ["web-server-01"]
