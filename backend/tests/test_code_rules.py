"""Tests du moteur de regles deterministes.

Aucun reseau, aucun OpenAI, aucun Wazuh : `rules.scan_content` est une
fonction pure.

Deux exigences egalement importantes :
1. detecter les motifs dangereux courants ;
2. ne pas crier au loup sur du code correct — un faux positif repete
   pousse le developpeur a desactiver l'extension.
"""

import pytest

from app.code import rules
from app.code.schemas import VULNERABILITY_CATEGORIES


def categories(hits) -> set[str]:
    return {hit.category for hit in hits}


def rule_ids(hits) -> set[str]:
    return {hit.rule_id for hit in hits}


# --------------------------------------------------------------------------
# Detections attendues
# --------------------------------------------------------------------------


def test_detecte_une_sql_injection_par_concatenation():
    """Le cas exact donne en exemple par l'utilisateur."""
    code = 'query = "SELECT * FROM users WHERE id=" + user_id\n'

    hits = rules.scan_content(code, "python")

    assert "sql_injection" in categories(hits)
    hit = next(h for h in hits if h.category == "sql_injection")
    assert hit.cwe == "CWE-89"
    assert hit.owasp.startswith("A03:2021")
    assert hit.base_severity == "CRITICAL"
    assert hit.location.line_start == 1
    assert "SELECT" in hit.location.snippet
    # Le finding explique, il n'assene pas.
    assert hit.why_dangerous
    assert hit.recommendations


def test_detecte_une_sql_injection_avec_valeur_entre_apostrophes():
    """Le fichier test.py de l'utilisateur, mot pour mot.

    La valeur est entouree d'apostrophes dans la requete : la chaine se
    termine donc par une apostrophe collee au guillemet fermant, juste
    avant l'operateur de concatenation. Ce cas -- le plus repandu des
    injections SQL -- passait au travers du motif SQLI001.
    """
    code = '''import sqlite3

username = input("Username: ")

conn = sqlite3.connect("users.db")

query = "SELECT * FROM users WHERE username = '" + username + "'"

cursor = conn.execute(query)
'''

    hits = rules.scan_content(code, "python")

    assert "sql_injection" in categories(hits)
    hit = next(h for h in hits if h.category == "sql_injection")
    assert hit.rule_id == "SQLI001"
    assert hit.base_severity == "CRITICAL"
    # La ligne signalee est celle de la requete, pas celle du input().
    assert hit.location.line_start == 7


@pytest.mark.parametrize(
    ("code", "language"),
    [
        (
            '''cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")\n''',
            "python",
        ),
        (
            '''String q = "SELECT * FROM t WHERE n = '" + n + "'";\n''',
            "java",
        ),
        (
            '''$q = "DELETE FROM users WHERE mail = '" . $mail . "'";\n''',
            "php",
        ),
    ],
)
def test_detecte_la_concatenation_avec_apostrophes_par_langage(code, language):
    """Le meme idiome, dans les autres langages pris en charge."""
    assert "sql_injection" in categories(rules.scan_content(code, language))


def test_detecte_une_sql_injection_par_f_string():
    code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'

    hits = rules.scan_content(code, "python")

    assert "sql_injection" in categories(hits)


def test_detecte_une_sql_injection_en_javascript():
    code = "const q = `SELECT * FROM users WHERE id = ${userId}`;\n"

    hits = rules.scan_content(code, "javascript")

    assert "sql_injection" in categories(hits)


def test_detecte_une_command_injection_python():
    code = 'os.system("ping " + host)\n'

    hits = rules.scan_content(code, "python")

    assert "command_injection" in categories(hits)
    hit = next(h for h in hits if h.category == "command_injection")
    assert hit.cwe == "CWE-78"


def test_detecte_shell_true():
    code = 'subprocess.run(cmd, shell=True)\n'

    hits = rules.scan_content(code, "python")

    assert "CMDI001" in rule_ids(hits)


def test_detecte_une_command_injection_javascript():
    code = "child_process.exec('ls ' + dir);\n"

    hits = rules.scan_content(code, "javascript")

    assert "command_injection" in categories(hits)


def test_detecte_une_xss_dom():
    code = "element.innerHTML = userInput;\n"

    hits = rules.scan_content(code, "javascript")

    assert "xss" in categories(hits)
    hit = next(h for h in hits if h.category == "xss")
    assert hit.cwe == "CWE-79"


def test_detecte_une_xss_php():
    code = "echo $_GET['name'];\n"

    hits = rules.scan_content(code, "php")

    assert "xss" in categories(hits)


def test_detecte_un_secret_en_dur():
    code = 'password = "Sup3rS3cretValue"\n'

    hits = rules.scan_content(code, "python")

    assert "hardcoded_secret" in categories(hits)


def test_detecte_une_cle_api_au_format_reconnu():
    code = 'OPENAI = "sk-abcdefghijklmnopqrstuvwxyz0123456789"\n'

    hits = rules.scan_content(code, "python")

    assert "SECRET002" in rule_ids(hits)


def test_le_secret_detecte_n_est_jamais_recopie_en_clair():
    """Le snippet stocke et renvoye passe par le sanitizer du projet."""
    code = 'api_key = "abcd1234efgh5678ijkl"\n'

    hits = rules.scan_content(code, "python")

    assert hits
    for hit in hits:
        assert "abcd1234efgh5678ijkl" not in hit.location.snippet
        assert "[REDACTED]" in hit.location.snippet


@pytest.mark.parametrize(
    "line, value",
    [
        ('AWS_ACCESS_KEY_ID = "AKIAQWERTYUIOPASDFGH"\n', "AKIAQWERTYUIOPASDFGH"),
        ('const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"\n', "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
        ('SLACK = "xoxb-123456789012-abcdefghijkl"\n', "xoxb-123456789012-abcdefghijkl"),
    ],
)
def test_une_cle_reconnue_a_son_format_n_est_jamais_recopiee_en_clair(line, value):
    """Regression : SECRET002 detecte ces formats, mais le sanitizer ne les
    connaissait pas. L'extrait stocke en base, renvoye par l'API et affiche
    dans la fiche de detail portait la cle en clair."""
    hits = rules.scan_content(line, "python")

    assert "SECRET002" in rule_ids(hits)
    for hit in hits:
        assert value not in hit.location.snippet
        assert "[REDACTED]" in hit.location.snippet


def test_detecte_un_path_traversal():
    code = 'content = open("/data/" + request.args.get("f")).read()\n'

    hits = rules.scan_content(code, "python")

    assert "path_traversal" in categories(hits)
    hit = next(h for h in hits if h.category == "path_traversal")
    assert hit.cwe == "CWE-22"


def test_detecte_un_eval_dangereux():
    code = "result = eval(user_expression)\n"

    hits = rules.scan_content(code, "python")

    assert "unsafe_eval" in categories(hits)


def test_detecte_une_cryptographie_faible():
    code = "digest = hashlib.md5(data).hexdigest()\n"

    hits = rules.scan_content(code, "python")

    assert "weak_cryptography" in categories(hits)


def test_detecte_une_configuration_non_securisee():
    code = 'requests.get(url, verify=False)\n'

    hits = rules.scan_content(code, "python")

    assert "insecure_configuration" in categories(hits)
    assert "CONF001" in rule_ids(hits)


def test_detecte_une_deserialisation_dangereuse():
    code = "data = pickle.loads(payload)\n"

    hits = rules.scan_content(code, "python")

    assert "insecure_deserialization" in categories(hits)


# --------------------------------------------------------------------------
# Absence de faux positifs evidents
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("code", "language"),
    [
        # Requete parametree : la reference de ce qu'il faut ecrire.
        ('cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n', "python"),
        ('cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])\n', "python"),
        # Commande sans shell ni concatenation.
        ('subprocess.run(["ping", host], shell=False)\n', "python"),
        # Secret lu dans l'environnement.
        ('password = os.getenv("DB_PASSWORD")\n', "python"),
        ('const apiKey = process.env.API_KEY;\n', "javascript"),
        # Placeholder evident.
        ('password = "changeme"\n', "python"),
        # Texte insere sans interpretation HTML.
        ("element.textContent = userInput;\n", "javascript"),
        # Echappement present.
        ("echo htmlspecialchars($_GET['name']);\n", "php"),
        # Hachage moderne.
        ("digest = hashlib.sha256(data).hexdigest()\n", "python"),
        # TLS verifie.
        ("requests.get(url, verify=True)\n", "python"),
        # YAML sur.
        ("config = yaml.safe_load(stream)\n", "python"),
        # Code anodin.
        ("def addition(a, b):\n    return a + b\n", "python"),
        ("const total = items.reduce((a, b) => a + b, 0);\n", "javascript"),
    ],
)
def test_pas_de_faux_positif_sur_du_code_correct(code, language):
    assert rules.scan_content(code, language) == []


def test_les_commentaires_sont_ignores():
    code = '# query = "SELECT * FROM users WHERE id=" + user_id\n'

    assert rules.scan_content(code, "python") == []


def test_le_marqueur_nosec_fait_taire_une_ligne():
    code = 'query = "SELECT * FROM users WHERE id=" + user_id  # nosec\n'

    assert rules.scan_content(code, "python") == []


# --------------------------------------------------------------------------
# Comportement du moteur
# --------------------------------------------------------------------------


def test_l_analyse_peut_se_limiter_aux_lignes_modifiees():
    code = (
        'a = 1\n'
        'query = "SELECT * FROM users WHERE id=" + user_id\n'
        'b = 2\n'
    )

    assert rules.scan_content(code, "python", changed_lines=[1, 3]) == []
    assert rules.scan_content(code, "python", changed_lines=[2])


def test_le_nombre_de_findings_est_plafonne():
    code = 'os.system("ping " + host)\n' * 50

    hits = rules.scan_content(code, "python", max_findings=5)

    assert len(hits) == 5


def test_le_catalogue_est_coherent():
    """Chaque regle est exploitable par l'interface et par les tests."""
    identifiers = [rule.rule_id for rule in rules.RULES]

    assert len(identifiers) == len(set(identifiers)), "identifiants dupliques"

    for rule in rules.RULES:
        assert rule.category in VULNERABILITY_CATEGORIES
        assert rule.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert 0 < rule.confidence <= 1
        assert rule.description
        assert rule.title
        assert rule.explanation
        assert rule.why_dangerous
        assert rule.potential_impact
        assert rule.recommendations


def test_les_huit_familles_demandees_sont_couvertes():
    couvertes = {rule.category for rule in rules.RULES}

    for attendue in (
        "sql_injection",
        "command_injection",
        "xss",
        "hardcoded_secret",
        "path_traversal",
        "unsafe_eval",
        "weak_cryptography",
        "insecure_configuration",
    ):
        assert attendue in couvertes
