"""Tests du pipeline de scan : validation, cache, persistance, risque.

Base SQLite temporaire (fixture `temp_db` de conftest), aucun reseau,
aucun appel OpenAI.
"""

import pytest
from pydantic import ValidationError

from app import store
from app.code import rules, scanner
from app.code.schemas import CodeScanRequest, content_hash_of
from app.config import settings

VULNERABLE = (
    "def get_user(user_id):\n"
    '    query = "SELECT * FROM users WHERE id=" + user_id\n'
    "    return db.execute(query)\n"
)

SAIN = (
    "def get_user(user_id):\n"
    '    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n'
)


def request_for(content: str, **overrides) -> CodeScanRequest:
    payload = {
        "file_path": "src/api/users.py",
        "language": "python",
        "content": content,
        "content_hash": content_hash_of(content),
        "workspace": "mon-projet",
    }
    payload.update(overrides)
    return CodeScanRequest(**payload)


# --------------------------------------------------------------------------
# Validation de la requete
# --------------------------------------------------------------------------


def test_un_contenu_vide_est_refuse():
    with pytest.raises(ValidationError) as exc:
        request_for("   ")

    assert "vide" in str(exc.value)


def test_un_hash_incorrect_est_refuse():
    """Jamais d'acceptation silencieuse : le cache en depend."""
    with pytest.raises(ValidationError) as exc:
        CodeScanRequest(
            file_path="a.py",
            language="python",
            content=VULNERABLE,
            content_hash="0" * 64,
        )

    assert "empreinte" in str(exc.value).lower()


def test_un_hash_absent_est_calcule():
    request = CodeScanRequest(
        file_path="a.py", language="python", content=VULNERABLE
    )

    assert request.content_hash == content_hash_of(VULNERABLE)


def test_un_contenu_trop_volumineux_est_refuse(monkeypatch):
    monkeypatch.setattr(settings, "code_max_content_bytes", 100)

    with pytest.raises(ValidationError) as exc:
        request_for("x = 1\n" * 200)

    assert "volumineux" in str(exc.value)


def test_un_chemin_vide_est_refuse():
    with pytest.raises(ValidationError):
        request_for(VULNERABLE, file_path="  ")


def test_le_nombre_de_lignes_est_calcule():
    assert request_for(VULNERABLE).line_count == 4


# --------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_un_scan_detecte_et_persiste_les_findings():
    result = await scanner.scan(request_for(VULNERABLE))

    assert result.cached is False
    assert result.analysis_status == "analyzed"
    assert result.findings_count == 1
    assert result.rules_version

    finding = result.findings[0]
    assert finding.category == "sql_injection"
    assert finding.severity == "CRITICAL"
    assert finding.risk_score > 0
    assert finding.source == "rule"
    assert finding.status == "open"
    assert finding.location.line_start == 2
    assert finding.file_path == "src/api/users.py"
    # Libelles francais fournis a l'extension.
    assert finding.severity_label == "CRITIQUE"
    assert finding.category_label == "SQL injection"
    assert finding.status_label == "Ouvert"
    assert finding.source_label == "Règle de détection"

    # Persistance effective.
    assert store.get_code_scan(result.scan_uid) is not None
    assert store.get_code_finding(finding.finding_uid) is not None


@pytest.mark.asyncio
async def test_un_scan_sans_probleme_ne_produit_aucun_finding():
    result = await scanner.scan(request_for(SAIN))

    assert result.findings == []
    assert result.counts.total == 0
    assert result.analysis_status == "analyzed"


@pytest.mark.asyncio
async def test_le_score_est_explique_facteur_par_facteur():
    result = await scanner.scan(request_for(VULNERABLE))

    factors = result.findings[0].risk_factors
    noms = {factor.name for factor in factors}

    assert "Gravité de la règle" in noms
    assert all(factor.detail for factor in factors)


@pytest.mark.asyncio
async def test_un_fichier_de_test_pese_moins_lourd():
    """Un motif dans un fichier de test reste signale, mais moins haut."""
    production = await scanner.scan(
        request_for(VULNERABLE, file_path="src/api/users.py")
    )
    tests = await scanner.scan(
        request_for(VULNERABLE, file_path="tests/test_users.py")
    )

    assert tests.findings[0].risk_score < production.findings[0].risk_score
    noms = {factor.name for factor in tests.findings[0].risk_factors}
    assert "Fichier de test" in noms


@pytest.mark.asyncio
async def test_un_fichier_sensible_pese_plus_lourd():
    banal = await scanner.scan(request_for(VULNERABLE, file_path="src/utils.py"))
    sensible = await scanner.scan(
        request_for(VULNERABLE, file_path="src/auth/login.py")
    )

    assert sensible.findings[0].risk_score > banal.findings[0].risk_score


@pytest.mark.asyncio
async def test_les_compteurs_par_severite_sont_justes():
    code = (
        'query = "SELECT * FROM t WHERE id=" + x\n'
        "requests.get(url, verify=False)\n"
        "digest = hashlib.md5(data).hexdigest()\n"
    )

    result = await scanner.scan(request_for(code))

    assert result.counts.total == result.findings_count
    assert result.counts.critical >= 1


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_un_meme_contenu_ressort_du_cache():
    first = await scanner.scan(request_for(VULNERABLE))
    second = await scanner.scan(request_for(VULNERABLE))

    assert first.cached is False
    assert second.cached is True
    # Meme scan, aucune nouvelle detection : pas de doublon en base.
    assert second.scan_uid == first.scan_uid
    assert second.findings_count == first.findings_count
    assert store.code_stats()["scans"] == 1


@pytest.mark.asyncio
async def test_un_contenu_modifie_declenche_un_nouveau_scan():
    first = await scanner.scan(request_for(VULNERABLE))
    second = await scanner.scan(request_for(VULNERABLE + "# modifie\n"))

    assert second.cached is False
    assert second.scan_uid != first.scan_uid
    assert store.code_stats()["scans"] == 2


@pytest.mark.asyncio
async def test_un_catalogue_de_regles_corrige_invalide_le_cache(monkeypatch):
    """Une regle reparee doit reanalyser les fichiers deja vus.

    Sans la version du catalogue dans la cle de cache, un fichier analyse
    avant la correction ressortait indefiniment avec l'ancien resultat :
    l'utilisateur relance son scan, le contenu n'a pas bouge, et le
    correctif reste invisible.
    """
    first = await scanner.scan(request_for(VULNERABLE))
    assert first.cached is False

    monkeypatch.setattr(rules, "RULES_VERSION", "9.9.9")
    second = await scanner.scan(request_for(VULNERABLE))

    assert second.cached is False
    assert second.scan_uid != first.scan_uid
    assert second.rules_version == "9.9.9"


@pytest.mark.asyncio
async def test_le_meme_contenu_dans_un_autre_fichier_est_bien_analyse():
    await scanner.scan(request_for(VULNERABLE, file_path="a.py"))
    autre = await scanner.scan(request_for(VULNERABLE, file_path="b.py"))

    assert autre.cached is False
    assert store.code_stats()["files"] == 2


# --------------------------------------------------------------------------
# Relecture et garde-fous
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_un_scan_peut_etre_relu_par_son_identifiant():
    created = await scanner.scan(request_for(VULNERABLE))

    relu = await scanner.get_scan(created.scan_uid)

    assert relu is not None
    assert relu.scan_uid == created.scan_uid
    assert relu.findings_count == created.findings_count


@pytest.mark.asyncio
async def test_un_scan_inconnu_ne_leve_pas():
    assert await scanner.get_scan("inexistant") is None


@pytest.mark.asyncio
async def test_l_analyse_desactivee_est_refusee_proprement(monkeypatch):
    monkeypatch.setattr(settings, "code_analysis_enabled", False)

    with pytest.raises(scanner.CodeAnalysisDisabledError) as exc:
        await scanner.scan(request_for(VULNERABLE))

    assert exc.value.status_code == 503
    assert "désactivée" in exc.value.message


@pytest.mark.asyncio
async def test_aucun_enrichissement_ia_n_est_applique_en_phase_1():
    """La demande est enregistree, jamais presentee comme un resultat."""
    result = await scanner.scan(request_for(VULNERABLE, ai_enrichment=True))

    assert result.ai_enrichment_requested is True
    assert result.ai_enrichment_applied is False
    assert result.model == ""
    # Tous les findings viennent des regles, aucun de l'IA.
    assert all(finding.source == "rule" for finding in result.findings)


@pytest.mark.asyncio
async def test_le_contenu_du_fichier_n_est_jamais_stocke():
    """Seules l'empreinte et les lignes signalees sont conservees."""
    secret_marker = "MARQUEUR_UNIQUE_DE_TEST_12345"
    code = f"x = 1  # {secret_marker}\n" + VULNERABLE

    result = await scanner.scan(request_for(code))

    row = store.get_code_scan(result.scan_uid)
    assert secret_marker not in str(row)
    for finding in result.findings:
        assert secret_marker not in finding.location.snippet


@pytest.mark.asyncio
async def test_l_analyse_peut_se_limiter_aux_lignes_modifiees():
    result = await scanner.scan(request_for(VULNERABLE, changed_lines=[1, 3]))

    assert result.findings == []


async def test_un_extrait_enregistre_en_clair_est_expurge_au_demarrage():
    """Regression : les extraits ecrits avant la correction du sanitizer
    gardaient la cle AWS en clair. `init_db` les expurge, une fois."""
    result = await scanner.scan(request_for('AWS_ACCESS_KEY_ID = "AKIAQWERTYUIOPASDFGH"\n'))
    uid = result.findings[0].finding_uid
    with store.get_connection() as connection:
        connection.execute(
            "UPDATE code_findings SET snippet = ? WHERE finding_uid = ?",
            ('AWS_ACCESS_KEY_ID = "AKIAQWERTYUIOPASDFGH"', uid),
        )

    store.init_db()
    store.init_db()

    snippet = store.get_code_finding(uid)["snippet"]
    assert "AKIAQWERTYUIOPASDFGH" not in snippet
    assert "[REDACTED]" in snippet
    # Expurgee du fichier aussi, pas seulement des lignes : `secure_delete`.
    with open(settings.database_path, "rb") as handle:
        assert b"AKIAQWERTYUIOPASDFGH" not in handle.read()
