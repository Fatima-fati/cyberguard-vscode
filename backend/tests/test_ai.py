"""Tests de l'agent IA.

L'API OpenAI n'est jamais appelee : les reponses sont simulees avec
httpx.MockTransport, exactement comme pour Wazuh.
"""

import asyncio
import json

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import routes, store
from app.ai import agent as ai_agent
from app.ai import risk_assessment
from app.ai.analyzer import analyze_context
from app.ai.openai_client import (
    AIAuthError,
    AIDisabledError,
    AIQuotaError,
    AIResponseError,
    AITimeoutError,
    AIUnavailableError,
    OpenAIClient,
)
from app.ai.sanitizer import REDACTED, redact_secrets, sanitize_alert_for_ai
from app.ai.schemas import (
    AIModelAnalysis,
    AlertContext,
    band_for_score,
    severity_for_score,
)
from app.config import settings
from app.main import app

from .conftest import make_alert

VALID_ANSWER = {
    "classification": "brute_force",
    "threat_type": "SSH brute force",
    "severity": "HIGH",
    "risk_score": 78,
    "confidence": 0.86,
    "summary": "Plusieurs echecs d'authentification depuis une meme adresse.",
    "explanation": "Le nombre de tentatives et leur regularite evoquent une attaque.",
    "indicators": ["25 alertes similaires", "compte root vise"],
    "recommendations": ["Bloquer l'adresse source", "Verifier les comptes"],
    "risk_factors": ["repetition elevee"],
}


@pytest.fixture(autouse=True)
def ai_configured(monkeypatch):
    """Une cle factice suffit : aucun appel reseau n'est realise."""
    monkeypatch.setattr(settings, "openai_api_key", "sk-test-cle-factice")
    monkeypatch.setattr(settings, "openai_model", "gpt-4o-mini")
    monkeypatch.setattr(settings, "ai_analysis_enabled", True)
    monkeypatch.setattr(settings, "ai_analysis_min_level", 7)
    ai_agent.reset_semaphore()
    yield
    ai_agent.reset_semaphore()


def openai_client(handler) -> OpenAIClient:
    """Client OpenAI dont le transport HTTP est simule."""
    client = OpenAIClient()
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


def answer(payload: dict, status: int = 200) -> httpx.Response:
    """Reponse au format de l'API chat completions."""
    return httpx.Response(
        status,
        json={
            "model": "gpt-4o-mini",
            "usage": {"total_tokens": 512},
            "choices": [{"message": {"content": json.dumps(payload)}}],
        },
    )


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


# --------------------------------------------------------------------------
# Seuils et bornes
# --------------------------------------------------------------------------


def test_les_seuils_de_risque_sont_centralises():
    """LOW 0-39, MEDIUM 40-69, HIGH 70-89, CRITICAL 90-100."""
    assert severity_for_score(0) == "LOW"
    assert severity_for_score(39) == "LOW"
    assert severity_for_score(40) == "MEDIUM"
    assert severity_for_score(69) == "MEDIUM"
    assert severity_for_score(70) == "HIGH"
    assert severity_for_score(89) == "HIGH"
    assert severity_for_score(90) == "CRITICAL"
    assert severity_for_score(100) == "CRITICAL"

    assert band_for_score(10) == "très faible"
    assert band_for_score(95) == "critique"


def test_le_score_est_toujours_borne_entre_0_et_100():
    assert AIModelAnalysis(risk_score=1500).risk_score == 100
    assert AIModelAnalysis(risk_score=-40).risk_score == 0
    assert AIModelAnalysis(risk_score="72").risk_score == 72
    assert AIModelAnalysis(risk_score=72.4).risk_score == 72


def test_un_score_inexploitable_invalide_l_analyse():
    """Mieux vaut refuser l'analyse que d'afficher un risque nul errone."""
    for invalide in ("pas un nombre", {"oups": 1}, [1], None):
        with pytest.raises(ValidationError):
            AIModelAnalysis(risk_score=invalide)


def test_la_confiance_est_normalisee():
    assert AIModelAnalysis(confidence=86).confidence == 0.86
    assert AIModelAnalysis(confidence=0.42).confidence == 0.42
    assert AIModelAnalysis(confidence=-1).confidence == 0.0
    assert AIModelAnalysis(confidence="?").confidence == 0.0


def test_une_classification_inconnue_devient_unknown():
    assert AIModelAnalysis(classification="Brute Force").classification == "brute_force"
    assert AIModelAnalysis(classification="teleportation").classification == "unknown"


def test_une_severite_fantaisiste_est_ramenee_a_low():
    assert AIModelAnalysis(severity="APOCALYPTIQUE").severity == "LOW"
    assert AIModelAnalysis(severity="critical").severity == "CRITICAL"


# --------------------------------------------------------------------------
# Nettoyage avant envoi au modele
# --------------------------------------------------------------------------


def test_les_mots_de_passe_sont_masques():
    cleaned = redact_secrets("user=admin password=SuperSecret123 action=login")

    assert "SuperSecret123" not in cleaned
    assert REDACTED in cleaned
    # Le nom du champ reste : c'est une information d'analyse.
    assert "password" in cleaned
    assert "user=admin" in cleaned


def test_les_tokens_et_cles_sont_masques():
    for secret, texte in [
        ("sk-abcdef0123456789abcdef", "cle sk-abcdef0123456789abcdef trouvee"),
        ("Zm9vYmFyYmF6cXV4", "Authorization: Bearer Zm9vYmFyYmF6cXV4"),
        ("MonToken42xyz", 'api_key: "MonToken42xyz"'),
    ]:
        cleaned = redact_secrets(texte)
        assert secret not in cleaned, texte
        assert REDACTED in cleaned


def test_une_cle_privee_est_masquee():
    texte = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabcdef\n-----END RSA PRIVATE KEY-----"
    assert "MIIEabcdef" not in redact_secrets(texte)


def test_un_jwt_est_masque():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijkl"
    assert jwt not in redact_secrets(f"cookie={jwt}")


def test_le_contexte_envoye_ne_contient_que_les_champs_utiles():
    alert = make_alert("a-1", level=10, description="Failed login")
    context = sanitize_alert_for_ai(alert, similar_alerts=12)

    assert context.alert_id == "a-1"
    assert context.rule_level == 10
    assert context.similar_alerts_24h == 12

    # Aucun credential de l'application ne circule.
    blob = context.model_dump_json().lower()
    assert settings.wazuh_api_password.lower() not in blob
    assert settings.indexer_password.lower() not in blob
    assert settings.openai_api_key.lower() not in blob


def test_le_secret_d_une_alerte_est_masque_avant_envoi():
    alert = make_alert("a-1")
    alert.full_log = "sshd: login user=root password=Hunter2 from 10.0.0.5"

    context = sanitize_alert_for_ai(alert)

    assert "Hunter2" not in context.full_log
    assert REDACTED in context.full_log


def test_un_journal_trop_long_est_tronque():
    alert = make_alert("a-1")
    alert.full_log = "A" * 5000

    context = sanitize_alert_for_ai(alert)

    assert len(context.full_log) < 2200
    assert context.full_log.endswith("[tronque]")


def test_une_alerte_incomplete_est_acceptee():
    alert = make_alert("a-1")
    alert.full_log = None
    alert.agent.ip = None
    alert.rule.id = None

    context = sanitize_alert_for_ai(alert)

    assert context.alert_id == "a-1"
    assert context.full_log is None
    assert context.rule_id is None


# --------------------------------------------------------------------------
# Appel du modele
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyse_d_une_alerte_valide():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        assert request.headers["authorization"].startswith("Bearer ")
        return answer(VALID_ANSWER)

    context = sanitize_alert_for_ai(make_alert("a-1", level=10), similar_alerts=25)
    analysis = await analyze_context(openai_client(handler), context)

    assert captured["path"].endswith("/chat/completions")
    assert captured["body"]["model"] == "gpt-4o-mini"
    assert captured["body"]["response_format"] == {"type": "json_object"}

    assert analysis.classification == "brute_force"
    assert analysis.severity == "HIGH"
    assert analysis.risk_score == 78
    assert analysis.confidence == 0.86
    assert len(analysis.recommendations) == 2


@pytest.mark.asyncio
async def test_la_cle_api_n_est_pas_dans_le_corps_envoye():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content.decode()
        return answer(VALID_ANSWER)

    context = sanitize_alert_for_ai(make_alert("a-1"))
    await analyze_context(openai_client(handler), context)

    assert settings.openai_api_key not in captured["body"]


@pytest.mark.asyncio
async def test_reponse_du_modele_invalide():
    def handler(request):
        return answer({"classification": "brute_force", "risk_score": {"oups": 1}})

    with pytest.raises(AIResponseError):
        await analyze_context(
            openai_client(handler), sanitize_alert_for_ai(make_alert("a-1"))
        )


@pytest.mark.asyncio
async def test_reponse_qui_n_est_pas_du_json():
    def handler(request):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "Bonjour, voici mon analyse"}}]},
        )

    with pytest.raises(AIResponseError):
        await analyze_context(
            openai_client(handler), sanitize_alert_for_ai(make_alert("a-1"))
        )


@pytest.mark.asyncio
async def test_structure_de_reponse_inattendue():
    def handler(request):
        return httpx.Response(200, json={"resultat": "?"})

    with pytest.raises(AIResponseError):
        await analyze_context(
            openai_client(handler), sanitize_alert_for_ai(make_alert("a-1"))
        )


@pytest.mark.asyncio
async def test_openai_indisponible():
    def handler(request):
        raise httpx.ConnectError("connexion refusee", request=request)

    with pytest.raises(AIUnavailableError):
        await analyze_context(
            openai_client(handler), sanitize_alert_for_ai(make_alert("a-1"))
        )


@pytest.mark.asyncio
async def test_timeout_openai():
    def handler(request):
        raise httpx.ReadTimeout("trop lent", request=request)

    with pytest.raises(AITimeoutError):
        await analyze_context(
            openai_client(handler), sanitize_alert_for_ai(make_alert("a-1"))
        )


@pytest.mark.asyncio
async def test_quota_depasse():
    def handler(request):
        return httpx.Response(429, json={"error": {"message": "rate limit"}})

    with pytest.raises(AIQuotaError):
        await analyze_context(
            openai_client(handler), sanitize_alert_for_ai(make_alert("a-1"))
        )


@pytest.mark.asyncio
async def test_cle_refusee():
    def handler(request):
        return httpx.Response(401, json={"error": {"message": "invalid api key"}})

    with pytest.raises(AIAuthError):
        await analyze_context(
            openai_client(handler), sanitize_alert_for_ai(make_alert("a-1"))
        )


@pytest.mark.asyncio
async def test_sans_cle_configuree(monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key", "")

    def handler(request):  # pragma: no cover - ne doit jamais etre appele
        raise AssertionError("aucun appel ne doit partir sans cle")

    with pytest.raises(AIDisabledError):
        await analyze_context(
            openai_client(handler), sanitize_alert_for_ai(make_alert("a-1"))
        )


# --------------------------------------------------------------------------
# Evaluation du risque
# --------------------------------------------------------------------------


def test_le_score_ne_recopie_pas_le_niveau_wazuh():
    context = AlertContext(alert_id="a-1", rule_level=10)
    analysis = AIModelAnalysis(classification="system_event", risk_score=5, severity="LOW")

    score, severity, _, _ = risk_assessment.combine(context, analysis)

    # Niveau 10/15 mais evenement anodin : le score reste modere.
    assert score != 10 * 100 / 15
    assert score < 30
    assert severity == "LOW"


def test_les_facteurs_de_risque_sont_explicites():
    context = AlertContext(
        alert_id="a-1",
        rule_level=12,
        rule_description="Multiple failed logins for root",
        full_log="Failed password for root from 203.0.113.5",
        similar_alerts_24h=30,
    )
    analysis = AIModelAnalysis(classification="brute_force", risk_score=85, severity="HIGH")

    score, severity, band, factors = risk_assessment.combine(context, analysis)
    names = {factor.name for factor in factors}

    assert "Niveau Wazuh" in names
    assert "Type d'événement" in names
    assert "Répétition" in names
    assert "Compte privilégié" in names
    assert "Exposition réseau" in names

    # Tous les facteurs aggravants presents : le risque est au moins eleve,
    # et severite comme libelle restent coherents avec le score.
    assert score >= 70
    assert severity == severity_for_score(score)
    assert band == band_for_score(score)


def test_une_ip_privee_ne_compte_pas_comme_exposition():
    context = AlertContext(
        alert_id="a-1", rule_level=5, full_log="connexion depuis 192.168.1.20"
    )
    _, factors = risk_assessment.compute_baseline(context)

    assert "Exposition reseau" not in {factor.name for factor in factors}


def test_un_journal_absent_est_signale_comme_contexte_limite():
    _, factors = risk_assessment.compute_baseline(AlertContext(alert_id="a-1"))

    assert "Contexte limité" in {factor.name for factor in factors}


# --------------------------------------------------------------------------
# Orchestration et cache
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyse_complete_et_persistance():
    def handler(request):
        return answer(VALID_ANSWER)

    alert = make_alert("a-1", level=10)
    store.save_alerts([alert])

    analysis = await ai_agent.analyze_alert(alert, client=openai_client(handler))

    assert analysis.alert_id == "a-1"
    assert analysis.classification == "brute_force"
    assert 0 <= analysis.risk_score <= 100
    assert analysis.ai_risk_score == 78
    assert analysis.baseline_risk_score > 0
    assert analysis.model == "gpt-4o-mini"
    assert analysis.agent_name == "srv-web"
    assert analysis.recommendations
    assert analysis.cached is False

    # Persistee et relisible.
    assert store.get_ai_analysis("a-1") is not None
    assert store.ai_analysis_stats()["analyzed"] == 1


@pytest.mark.asyncio
async def test_une_alerte_deja_analysee_ne_rappelle_pas_openai():
    calls = {"count": 0}

    def handler(request):
        calls["count"] += 1
        return answer(VALID_ANSWER)

    alert = make_alert("a-1", level=10)
    client = openai_client(handler)

    first = await ai_agent.analyze_alert(alert, client=client)
    second = await ai_agent.analyze_alert(alert, client=client)

    assert calls["count"] == 1, "le cache doit eviter un second appel"
    assert second.cached is True
    assert second.risk_score == first.risk_score


@pytest.mark.asyncio
async def test_force_relance_une_analyse():
    calls = {"count": 0}

    def handler(request):
        calls["count"] += 1
        return answer(VALID_ANSWER)

    alert = make_alert("a-1", level=10)
    client = openai_client(handler)

    await ai_agent.analyze_alert(alert, client=client)
    await ai_agent.analyze_alert(alert, client=client, force=True)

    assert calls["count"] == 2


@pytest.mark.asyncio
async def test_le_filtre_de_niveau_evite_les_analyses_inutiles(monkeypatch):
    monkeypatch.setattr(settings, "ai_analysis_min_level", 7)

    assert ai_agent.should_analyze(make_alert("a-1", level=3)) is False
    assert ai_agent.should_analyze(make_alert("a-2", level=7)) is True

    monkeypatch.setattr(settings, "ai_analysis_enabled", False)
    assert ai_agent.should_analyze(make_alert("a-3", level=12)) is False


@pytest.mark.asyncio
async def test_une_erreur_ia_ne_bloque_pas_la_surveillance(monkeypatch):
    """analyze_new_alerts ne doit jamais lever : le poller l'appelle detache."""

    async def failing(alert, force=False, client=None):
        raise AIUnavailableError("OpenAI injoignable")

    monkeypatch.setattr(ai_agent, "analyze_alert", failing)

    results = await ai_agent.analyze_new_alerts(
        [make_alert("a-1", level=12), make_alert("a-2", level=12)]
    )

    assert results == []


@pytest.mark.asyncio
async def test_une_erreur_inattendue_est_aussi_absorbee(monkeypatch):
    async def exploding(alert, force=False, client=None):
        raise RuntimeError("bug inattendu")

    monkeypatch.setattr(ai_agent, "analyze_alert", exploding)

    assert await ai_agent.analyze_new_alerts([make_alert("a-1", level=12)]) == []


@pytest.mark.asyncio
async def test_le_poller_continue_meme_si_l_ia_echoue(controller_factory, monkeypatch):
    """Test d'integration : la boucle de surveillance survit a une panne IA."""
    from .conftest import FakeWazuhClient

    async def failing(alerts):
        raise AIUnavailableError("OpenAI injoignable")

    monkeypatch.setattr(ai_agent, "analyze_new_alerts", failing)

    alerts = [make_alert("a-1", level=12), make_alert("a-2", level=12)]
    controller = controller_factory(FakeWazuhClient(batches=[alerts]))
    await controller._load_state()

    new_alerts = await controller.scan_once()
    await asyncio.sleep(0.05)  # laisse la tache detachee echouer

    assert len(new_alerts) == 2, "les alertes sont collectees malgre l'echec IA"
    assert store.count_alerts() == 2
    assert controller.status().errors == 0, "l'erreur IA ne compte pas comme erreur poller"
    assert controller.status().last_error is None


@pytest.mark.asyncio
async def test_les_stats_agregent_les_analyses():
    def handler(request):
        return answer(VALID_ANSWER)

    client = openai_client(handler)
    for index in range(3):
        await ai_agent.analyze_alert(make_alert(f"a-{index}", level=10), client=client)

    stats = await ai_agent.get_stats()

    assert stats.analyzed == 3
    assert stats.average_risk_score > 0
    assert stats.enabled is True
    assert stats.model == "gpt-4o-mini"


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------


def test_endpoint_analyze_par_identifiant(client, monkeypatch):
    def handler(request):
        return answer(VALID_ANSWER)

    fake = openai_client(handler)
    monkeypatch.setattr("app.ai.agent.get_openai_client", lambda: fake)

    store.save_alerts([make_alert("a-1", level=10)])

    response = client.post("/api/ai/analyze", json={"alert_id": "a-1"})

    assert response.status_code == 200
    body = response.json()
    assert body["alert_id"] == "a-1"
    assert body["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert 0 <= body["risk_score"] <= 100
    assert body["recommendations"]


def test_endpoint_analyze_avec_alerte_complete(client, monkeypatch):
    def handler(request):
        return answer(VALID_ANSWER)

    fake = openai_client(handler)
    monkeypatch.setattr("app.ai.agent.get_openai_client", lambda: fake)

    alert = make_alert("a-2", level=10)
    response = client.post(
        "/api/ai/analyze", json={"alert": alert.model_dump(mode="json")}
    )

    assert response.status_code == 200
    assert response.json()["alert_id"] == "a-2"


def test_endpoint_analyze_alerte_inconnue(client, monkeypatch):
    """Une alerte absente de la base ET de l'Indexer donne 404.

    Le client Wazuh est bouchonne : sans lui, la route tente une connexion
    reelle vers l'Indexer avant d'atteindre le chemin 404, et le test
    renvoyait 503 ou 404 selon que la machine avait un Indexer joignable.
    Un test dont le resultat depend de l'environnement ne prouve rien, et
    un appel sortant depuis une suite de tests est un probleme en soi.
    """

    class IndexerSansCetteAlerte:
        """Indexer joignable qui ne connait pas l'alerte demandee."""

        def __init__(self) -> None:
            self.asked: list[str] = []

        async def get_alert_by_id(self, alert_id: str):
            self.asked.append(alert_id)
            return None

    fake = IndexerSansCetteAlerte()
    monkeypatch.setattr(routes, "get_wazuh_client", lambda: fake)

    response = client.post("/api/ai/analyze", json={"alert_id": "jamais-vue"})

    assert response.status_code == 404
    assert "introuvable" in response.json()["detail"]["error"]
    # La route a bien consulte l'Indexer avant de conclure : c'est ce repli
    # qui distingue « inconnue partout » de « pas encore persistee ».
    assert fake.asked == ["jamais-vue"]


def test_endpoint_analyze_openai_indisponible(client, monkeypatch):
    def handler(request):
        raise httpx.ConnectError("refuse", request=request)

    fake = openai_client(handler)
    monkeypatch.setattr("app.ai.agent.get_openai_client", lambda: fake)

    store.save_alerts([make_alert("a-1", level=10)])
    response = client.post("/api/ai/analyze", json={"alert_id": "a-1"})

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert "injoignable" in detail["error"]
    assert "Traceback" not in response.text


def test_les_endpoints_ia_ne_divulguent_aucune_cle(client, monkeypatch):
    def handler(request):
        return answer(VALID_ANSWER)

    fake = openai_client(handler)
    monkeypatch.setattr("app.ai.agent.get_openai_client", lambda: fake)
    store.save_alerts([make_alert("a-1", level=10)])

    for response in (
        client.post("/api/ai/analyze", json={"alert_id": "a-1"}),
        client.get("/api/ai/alerts"),
        client.get("/api/ai/stats"),
        client.get("/api/config"),
    ):
        assert settings.openai_api_key not in response.text
        assert "sk-" not in response.text
        assert "authorization" not in response.text.lower()


def test_endpoint_liste_des_analyses(client, monkeypatch):
    def handler(request):
        return answer(VALID_ANSWER)

    fake = openai_client(handler)
    monkeypatch.setattr("app.ai.agent.get_openai_client", lambda: fake)

    store.save_alerts([make_alert("a-1", level=10)])
    client.post("/api/ai/analyze", json={"alert_id": "a-1"})

    body = client.get("/api/ai/alerts").json()
    assert len(body) == 1
    assert body[0]["alert_id"] == "a-1"

    # Filtre par score : rien au-dessus de 100.
    assert client.get("/api/ai/alerts?min_score=100").json() == []


def test_endpoint_stats(client):
    body = client.get("/api/ai/stats").json()

    assert set(body) >= {
        "analyzed",
        "low",
        "medium",
        "high",
        "critical",
        "average_risk_score",
        "enabled",
        "model",
    }
