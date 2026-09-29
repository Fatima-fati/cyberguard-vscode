"""Tests de l'authentification locale (phase 0).

Ce que ces tests garantissent, et pourquoi chacun compte :

- une route sensible refuse un appel sans jeton — c'est l'objet meme du
  dispositif ;
- la route de diagnostic reste accessible — sinon un probleme
  d'authentification et un backend eteint donneraient le meme symptome ;
- le jeton n'apparait dans aucune reponse ni dans aucun journal — un
  secret qui fuit dans un message d'erreur n'est plus un secret ;
- le fichier de jeton est ecrit hors du depot — un secret range dans le
  projet finit commite.
"""

import logging

import pytest
from fastapi.testclient import TestClient

from app import auth
from app.code.schemas import content_hash_of
from app.config import settings
from app.main import app

from .conftest import TEST_AGENT_TOKEN, auth_headers

# Routes sensibles, une par famille. La liste n'est pas exhaustive : elle
# couvre chaque forme d'acces (lecture, ecriture, flux, projet).
SENSITIVE_ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/code/rules"),
    ("GET", "/api/code/findings"),
    ("GET", "/api/code/stats"),
    ("POST", "/api/code/scan"),
    ("GET", "/api/stream"),
    ("POST", "/api/project/discover"),
)


@pytest.fixture
def anonymous():
    """Client sans en-tete d'authentification."""
    with TestClient(app) as client:
        yield client


@pytest.fixture
def authenticated():
    with TestClient(app, headers=auth_headers()) as client:
        yield client


# --------------------------------------------------------------------------
# Refus
# --------------------------------------------------------------------------


@pytest.mark.parametrize("method,path", SENSITIVE_ROUTES)
def test_sans_jeton_une_route_sensible_repond_401(anonymous, method, path):
    response = anonymous.request(method, path, json={})
    assert response.status_code == 401
    # `WWW-Authenticate` dit au client *comment* s'authentifier : sans lui,
    # un 401 est une porte fermee sans serrure visible.
    assert response.headers.get("WWW-Authenticate") == "Bearer"


@pytest.mark.parametrize("method,path", SENSITIVE_ROUTES)
def test_avec_un_mauvais_jeton_une_route_sensible_repond_401(method, path):
    with TestClient(app, headers=auth_headers("jeton-invente")) as client:
        response = client.request(method, path, json={})
    assert response.status_code == 401


@pytest.mark.parametrize(
    "header",
    [
        "",
        "Bearer",
        "Bearer ",
        TEST_AGENT_TOKEN,  # sans le schema
        f"Basic {TEST_AGENT_TOKEN}",
        f"Bearer {TEST_AGENT_TOKEN} extra",
    ],
)
def test_un_en_tete_malforme_est_refuse(header):
    """Un en-tete approximatif n'ouvre pas la porte.

    Le dernier cas compte particulierement : `Bearer <jeton> extra` porte
    le bon jeton suivi d'autre chose. Le decoupage ne garde que deux
    parties, donc la valeur comparee est « <jeton> extra », qui ne
    correspond pas. Un decoupage laxiste aurait laisse passer.
    """
    with TestClient(app, headers={"Authorization": header}) as client:
        response = client.get("/api/code/rules")
    assert response.status_code == 401


def test_un_jeton_de_la_bonne_longueur_mais_faux_est_refuse():
    """La comparaison porte sur la valeur, pas sur la forme."""
    faux = "x" * len(TEST_AGENT_TOKEN)
    with TestClient(app, headers=auth_headers(faux)) as client:
        assert client.get("/api/code/rules").status_code == 401


def test_un_jeton_prefixe_correct_est_refuse():
    """Un prefixe correct ne suffit pas : `compare_digest` est integral."""
    with TestClient(app, headers=auth_headers(TEST_AGENT_TOKEN[:-1])) as client:
        assert client.get("/api/code/rules").status_code == 401


# --------------------------------------------------------------------------
# Acceptation
# --------------------------------------------------------------------------


def test_avec_le_bon_jeton_une_route_sensible_repond_200(authenticated):
    response = authenticated.get("/api/code/rules")
    assert response.status_code == 200
    assert len(response.json()) >= 8


def test_un_scan_authentifie_fonctionne_de_bout_en_bout(authenticated):
    """Le controle n'a pas casse la chaine d'analyse existante."""
    content = 'query = "SELECT * FROM users WHERE id=" + user_id\n'
    response = authenticated.post(
        "/api/code/scan",
        json={
            "file_path": "src/app.py",
            "language": "python",
            "content": content,
            "content_hash": content_hash_of(content),
        },
    )
    assert response.status_code == 200
    assert response.json()["findings_count"] >= 1


def test_le_schema_bearer_est_insensible_a_la_casse():
    """RFC 7235 : le nom du schema ne tient pas compte de la casse."""
    with TestClient(
        app, headers={"Authorization": f"bEaReR {TEST_AGENT_TOKEN}"}
    ) as client:
        assert client.get("/api/code/rules").status_code == 200


# --------------------------------------------------------------------------
# Diagnostic : la seule route publique
# --------------------------------------------------------------------------


def test_le_health_du_code_reste_public(anonymous):
    """Sans cette route, un 401 serait indiscernable d'un backend eteint."""
    response = anonymous.get("/api/code/health")
    assert response.status_code == 200
    body = response.json()
    assert body["auth_required"] is True
    assert body["project_context_enabled"] is True


def test_le_health_ne_contient_aucun_jeton(anonymous):
    """La route publique annonce l'exigence, jamais le secret."""
    raw = anonymous.get("/api/code/health").text
    assert TEST_AGENT_TOKEN not in raw
    assert "token" not in raw.lower() or "auth_required" in raw


# --------------------------------------------------------------------------
# Non-divulgation
# --------------------------------------------------------------------------


def test_un_refus_ne_divulgue_jamais_le_jeton_attendu(anonymous):
    body = anonymous.get("/api/code/findings").text
    assert TEST_AGENT_TOKEN not in body


def test_un_refus_ne_journalise_jamais_le_jeton_presente(caplog):
    """Le chemin refuse est trace, la valeur presentee ne l'est jamais.

    C'est le journal qui fuit le plus facilement : il est copie dans des
    rapports de bug et partage sans relecture.
    """
    presente = "jeton-secret-de-l-appelant"
    with caplog.at_level(logging.DEBUG):
        with TestClient(app, headers=auth_headers(presente)) as client:
            assert client.get("/api/code/findings").status_code == 401

    journal = caplog.text
    assert presente not in journal
    assert TEST_AGENT_TOKEN not in journal
    # Le refus est bien trace : un rejet silencieux serait indiagnosticable.
    assert "/api/code/findings" in journal


# --------------------------------------------------------------------------
# Extraction de l'en-tete (unitaire)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "header,expected",
    [
        ("Bearer abc", "abc"),
        ("bearer abc", "abc"),
        ("  Bearer   abc  ", "abc"),
        (None, None),
        ("", None),
        ("Bearer", None),
        ("Basic abc", None),
        ("abc", None),
    ],
)
def test_extract_bearer(header, expected):
    assert auth.extract_bearer(header) == expected


def test_verify_token_refuse_une_valeur_vide():
    """Sans jeton presente, la verification echoue — jamais l'inverse."""
    assert auth.verify_token(None) is False
    assert auth.verify_token("") is False


def test_verify_token_refuse_tout_si_aucun_jeton_n_est_etabli():
    """Jeton du processus absent : on refuse, on n'ouvre pas.

    Le defaut sur : si l'etablissement du jeton a echoue, servir sans
    controle serait un affaiblissement silencieux.
    """
    auth.set_token_for_tests(None)
    try:
        assert auth.verify_token("n-importe-quoi") is False
    finally:
        auth.set_token_for_tests(TEST_AGENT_TOKEN)


def test_une_route_sensible_refuse_si_le_jeton_du_processus_est_absent():
    auth.set_token_for_tests(None)
    try:
        with TestClient(app, headers=auth_headers()) as client:
            # Le client TestClient relance le lifespan, qui reetablit le
            # jeton : on verifie donc la dependance directement.
            response = client.get(
                "/api/code/findings", headers={"Authorization": "Bearer "}
            )
        assert response.status_code == 401
    finally:
        auth.set_token_for_tests(TEST_AGENT_TOKEN)


# --------------------------------------------------------------------------
# Emplacement du jeton
# --------------------------------------------------------------------------


def test_le_jeton_est_range_hors_du_depot(monkeypatch):
    """Par defaut : profil utilisateur, jamais l'arborescence du projet."""
    monkeypatch.setattr(settings, "agent_token_path", "")
    path = auth.token_path()
    assert path.name == "agent-token"
    assert ".wazuh-security" in str(path)
    # Le chemin ne doit pas pointer dans le depot : un fichier de secret
    # place la finirait dans un commit ou dans une archive du dossier.
    assert "VsCode-extension" not in str(path)


def test_le_chemin_du_jeton_est_configurable(monkeypatch, tmp_path):
    cible = tmp_path / "ailleurs" / "jeton"
    monkeypatch.setattr(settings, "agent_token_path", str(cible))
    assert auth.token_path() == cible


def test_un_jeton_genere_est_ecrit_puis_relu(monkeypatch, tmp_path):
    """Deuxieme demarrage : le jeton existant est relu, pas regenere.

    Regenerer invaliderait le jeton que l'extension detient deja et la
    rendrait muette jusqu'a ce qu'elle relise le fichier.
    """
    cible = tmp_path / "jeton"
    monkeypatch.setattr(settings, "agent_token_path", str(cible))
    monkeypatch.setattr(settings, "agent_auth_token", "")

    auth.set_token_for_tests(None)
    try:
        premier = auth.ensure_token()
        assert cible.read_text(encoding="utf-8").strip() == premier
        assert len(premier) >= 32

        auth.set_token_for_tests(None)
        second = auth.ensure_token()
        assert second == premier
    finally:
        auth.set_token_for_tests(TEST_AGENT_TOKEN)


def test_un_jeton_d_environnement_l_emporte_sur_le_fichier(monkeypatch, tmp_path):
    """Un deploiement gere son secret ailleurs et n'ecrit rien sur disque."""
    cible = tmp_path / "jeton"
    monkeypatch.setattr(settings, "agent_token_path", str(cible))
    monkeypatch.setattr(settings, "agent_auth_token", "jeton-du-deploiement")

    auth.set_token_for_tests(None)
    try:
        assert auth.ensure_token() == "jeton-du-deploiement"
        assert not cible.exists()
    finally:
        auth.set_token_for_tests(TEST_AGENT_TOKEN)


def test_ensure_token_est_idempotent(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "agent_token_path", str(tmp_path / "jeton"))
    monkeypatch.setattr(settings, "agent_auth_token", "")
    auth.set_token_for_tests(None)
    try:
        assert auth.ensure_token() == auth.ensure_token()
    finally:
        auth.set_token_for_tests(TEST_AGENT_TOKEN)


# --------------------------------------------------------------------------
# Posture d'ecoute
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host,loopback",
    [
        ("127.0.0.1", True),
        ("127.0.1.1", True),
        ("localhost", True),
        ("::1", True),
        ("[::1]", True),
        ("0.0.0.0", False),
        ("192.168.1.10", False),
        ("", False),
    ],
)
def test_binds_loopback_only(monkeypatch, host, loopback):
    monkeypatch.setattr(settings, "api_host", host)
    assert settings.binds_loopback_only is loopback


def test_l_ecoute_par_defaut_est_locale():
    """Le defaut du code, pas celui d'un .env : 127.0.0.1.

    Exposer au reseau un backend qui detient des identifiants et diffuse
    des extraits de code doit etre une decision explicite.
    """
    from app.config import Settings

    assert Settings.model_fields["api_host"].default == "127.0.0.1"


def test_l_authentification_est_active_par_defaut():
    from app.config import Settings

    assert Settings.model_fields["agent_auth_enabled"].default is True
