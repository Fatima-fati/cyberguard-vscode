"""Classement deterministe d'un projet (phase 1).

Tests unitaires du module `app.project.discovery` : aucune base, aucune
route, aucun reseau. Ils portent sur la seule question qu'il traite —
*qu'est-ce que ce projet, d'apres les chemins et les manifestes ?*

Le fil conducteur : **rien n'est affirme sans preuve.** Plusieurs tests
verifient l'absence d'une detection autant que sa presence, parce qu'un
framework annonce a tort est plus couteux qu'un framework manque.
"""

import pytest

from app.project import discovery
from app.project.ai_contract import build_ai_project_context
from app.project.schemas import (
    ClassifiedFile,
    IndexedFile,
    ManifestEvidence,
    ProjectSecurityContext,
)


def index(*paths: str) -> list[IndexedFile]:
    return [IndexedFile(path=path) for path in paths]


def classify(*paths: str) -> list[ClassifiedFile]:
    return [discovery.classify_path(path) for path in paths]


# --------------------------------------------------------------------------
# Langages
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,language",
    [
        ("src/app.py", "python"),
        ("src/app.pyi", "python"),
        ("src/index.js", "javascript"),
        ("src/App.jsx", "javascript"),
        ("src/main.mjs", "javascript"),
        ("src/extension.ts", "typescript"),
        ("src/App.tsx", "typescript"),
        ("Main.java", "java"),
        ("index.php", "php"),
        ("main.go", "go"),
        ("Program.cs", "csharp"),
        ("app.rb", "ruby"),
        ("schema.sql", "sql"),
        ("README.md", None),
        ("logo.png", None),
        ("Makefile", None),
    ],
)
def test_langage_par_extension(path, language):
    assert discovery.language_for_path(path) == language


def test_les_langages_detectes_sont_ceux_reellement_presents():
    """Un langage n'est liste que si un fichier l'atteste.

    La difference avec « langage pris en charge » est la raison d'etre de
    ce test : le moteur connait Java, ce projet n'en contient pas, Java ne
    doit pas apparaitre.
    """
    languages = discovery.detect_languages(
        classify("src/a.py", "src/b.py", "src/c.ts", "README.md")
    )

    noms = [item.language for item in languages]
    assert noms == ["python", "typescript"]
    assert "java" not in noms

    python = languages[0]
    assert python.file_count == 2
    assert python.share == 67


def test_les_proportions_ignorent_les_fichiers_sans_langage():
    """Compter un `.md` comme un langage faussserait les parts."""
    languages = discovery.detect_languages(
        classify("a.py", "README.md", "LICENSE", "logo.png")
    )
    assert len(languages) == 1
    assert languages[0].share == 100


def test_un_projet_sans_code_ne_detecte_aucun_langage():
    assert discovery.detect_languages(classify("README.md", "LICENSE")) == []
    assert discovery.primary_language([]) is None


def test_la_couverture_d_analyse_est_annoncee_telle_quelle():
    """`analysis_supported` doit refleter les regles reelles.

    Annoncer une couverture inexistante induirait l'utilisateur en erreur
    sur sa propre exposition — exactement ce que le projet s'interdit.
    """
    languages = discovery.detect_languages(classify("a.py", "b.go"))
    par_nom = {item.language: item for item in languages}

    assert par_nom["python"].analysis_supported is True
    # Go est reconnu comme langage present, mais aucune regle ne le couvre.
    assert par_nom["go"].analysis_supported is False


def test_le_langage_principal_est_le_plus_represente():
    languages = discovery.detect_languages(
        classify("a.ts", "b.ts", "c.ts", "d.py")
    )
    assert discovery.primary_language(languages) == "typescript"


# --------------------------------------------------------------------------
# Fichiers sensibles — la regle la plus importante
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,type_attendu",
    [
        (".env", "environment-secrets"),
        (".env.local", "environment-secrets"),
        (".env.production", "environment-secrets"),
        ("backend/.env", "environment-secrets"),
        ("certs/server.pem", "private-key-or-certificate"),
        ("certs/server.key", "private-key"),
        ("store.p12", "keystore"),
        ("store.pfx", "keystore"),
        ("store.jks", "keystore"),
        (".ssh/id_rsa", "ssh-private-key"),
        (".ssh/id_ed25519", "ssh-private-key"),
        (".npmrc", "registry-credentials"),
        (".pypirc", "registry-credentials"),
        (".netrc", "host-credentials"),
        (".htpasswd", "password-file"),
        ("credentials", "credentials"),
        ("credentials.json", "credentials"),
        ("secrets.yml", "secrets"),
    ],
)
def test_un_fichier_sensible_est_classe_sensible(path, type_attendu):
    entry = discovery.classify_path(path)
    assert entry.kind == "sensitive"
    assert entry.type == type_attendu
    # La raison est affichee a l'utilisateur : elle ne doit jamais etre vide.
    assert entry.reason


@pytest.mark.parametrize(
    "path",
    [".env.example", ".env.sample", ".env.template", ".env.dist"],
)
def test_un_modele_d_environnement_n_est_pas_sensible(path):
    """Un `.env.example` a pour raison d'etre de ne rien contenir.

    Le classer sensible banaliserait la liste, et une liste banalisee
    n'est plus lue — le contraire de l'effet recherche.
    """
    assert discovery.classify_path(path).kind != "sensitive"


def test_le_classement_sensible_passe_avant_tout_le_reste():
    """L'ordre des controles porte une decision, pas une commodite.

    Un `.env` pourrait passer pour une configuration. S'il atterrissait
    dans `configuration_files`, il rejoindrait une liste ou les phases
    suivantes s'autorisent a lire.
    """
    entry = discovery.classify_path("config/.env")
    assert entry.kind == "sensitive"
    assert entry.kind != "config"


def test_une_cle_privee_dans_un_dossier_de_source_reste_sensible():
    """Le classement suit le nom, pas l'emplacement."""
    assert discovery.classify_path("src/deploy/server.key").kind == "sensitive"


def test_le_classement_ne_contient_jamais_de_contenu():
    """Un fichier classe porte un chemin, un type et une raison. C'est tout.

    `ClassifiedFile` n'a structurellement aucun champ de contenu : ce test
    fige cette absence, pour qu'un ajout futur soit un choix conscient.
    """
    champs = set(ClassifiedFile.model_fields)
    assert champs == {"path", "kind", "type", "reason"}


# --------------------------------------------------------------------------
# Manifestes, configuration, infrastructure
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,type_attendu",
    [
        ("package.json", "npm-manifest"),
        ("package-lock.json", "npm-lockfile"),
        ("requirements.txt", "pip-requirements"),
        ("pyproject.toml", "python-project"),
        ("pom.xml", "maven-manifest"),
        ("composer.json", "composer-manifest"),
        ("go.mod", "go-manifest"),
        ("Gemfile", "bundler-manifest"),
        ("Api.csproj", "dotnet-manifest"),
    ],
)
def test_un_manifeste_est_reconnu(path, type_attendu):
    entry = discovery.classify_path(path)
    assert entry.kind == "manifest"
    assert entry.type == type_attendu


@pytest.mark.parametrize(
    "path,kind,type_attendu",
    [
        ("Dockerfile", "infra", "docker"),
        ("docker-compose.yml", "infra", "docker-compose"),
        ("infra/main.tf", "infra", "terraform"),
        (".github/workflows/ci.yml", "infra", "github-workflow"),
        ("tsconfig.json", "config", "typescript-config"),
        ("vite.config.ts", "config", "vite-config"),
        ("webpack.config.js", "config", "webpack-config"),
        (".gitignore", "config", "git-ignore"),
        ("angular.json", "config", "angular-config"),
    ],
)
def test_configuration_et_infrastructure(path, kind, type_attendu):
    entry = discovery.classify_path(path)
    assert entry.kind == kind
    assert entry.type == type_attendu


@pytest.mark.parametrize(
    "path",
    [
        "tests/test_app.py",
        "test/app.test.ts",
        "src/app.spec.ts",
        "__tests__/render.js",
        "spec/models_spec.rb",
    ],
)
def test_un_test_est_classe_test_et_pas_source(path):
    """Un finding dans un test ne porte pas le risque d'un finding en prod."""
    assert discovery.classify_path(path).kind == "test"


def test_un_fichier_source_ordinaire_est_classe_source():
    assert discovery.classify_path("src/services/users.py").kind == "source"


def test_un_fichier_inconnu_est_classe_other_sans_inventer_de_raison():
    entry = discovery.classify_path("assets/logo.png")
    assert entry.kind == "other"
    assert entry.reason == ""


# --------------------------------------------------------------------------
# Frameworks — la preuve avant l'affirmation
# --------------------------------------------------------------------------


def test_un_framework_est_detecte_par_dependance_declaree():
    frameworks = discovery.detect_frameworks(
        [
            ManifestEvidence(
                path="package.json",
                ecosystem="npm",
                dependency_names=["react", "react-dom", "lodash"],
            )
        ],
        [],
    )

    assert len(frameworks) == 1
    react = frameworks[0]
    assert react.framework == "React"
    assert react.confidence == 0.9
    # La preuve accompagne la detection jusqu'a l'interface.
    assert "react" in react.evidence
    assert react.source == "package.json"


def test_fastapi_est_detecte_depuis_requirements():
    frameworks = discovery.detect_frameworks(
        [
            ManifestEvidence(
                path="backend/requirements.txt",
                ecosystem="pypi",
                dependency_names=["fastapi", "uvicorn", "pydantic"],
            )
        ],
        [],
    )
    assert [item.framework for item in frameworks] == ["FastAPI"]
    assert frameworks[0].source == "backend/requirements.txt"


def test_aucun_framework_sans_preuve():
    """Un projet Python sans dependance de framework n'en declare aucun."""
    assert discovery.detect_frameworks([], classify("src/a.py", "src/b.py")) == []


def test_une_dependance_approchante_ne_prouve_pas_un_framework():
    """Correspondance exacte, jamais une sous-chaine.

    `react-scripts` est un outil de build, pas React. `flask-cors` est une
    extension, pas une application Flask. Accepter ces noms produirait des
    detections fausses sur des projets tres courants.
    """
    frameworks = discovery.detect_frameworks(
        [
            ManifestEvidence(
                path="package.json",
                dependency_names=["react-scripts", "flask-cors", "expressive"],
            )
        ],
        [],
    )
    assert frameworks == []


def test_un_fichier_de_configuration_dedie_vaut_une_preuve_plus_faible():
    """Un `angular.json` peut survivre au retrait d'Angular : 0,7, pas 0,9."""
    frameworks = discovery.detect_frameworks([], classify("angular.json"))
    assert len(frameworks) == 1
    assert frameworks[0].framework == "Angular"
    assert frameworks[0].confidence == 0.7
    assert frameworks[0].evidence == "fichier de configuration dedie"


def test_la_dependance_l_emporte_sur_le_fichier_de_configuration():
    """Deux preuves pour un framework : on garde la plus forte."""
    frameworks = discovery.detect_frameworks(
        [ManifestEvidence(path="package.json", dependency_names=["@angular/core"])],
        classify("angular.json"),
    )
    assert len(frameworks) == 1
    assert frameworks[0].confidence == 0.9


def test_aucun_framework_n_atteint_une_confiance_totale():
    """Un manifeste peut declarer une dependance que le code n'utilise plus.

    Cette phase ne lit pas le code : elle ne peut donc pas etre certaine.
    """
    frameworks = discovery.detect_frameworks(
        [ManifestEvidence(path="package.json", dependency_names=["react", "express"])],
        classify("angular.json"),
    )
    assert frameworks
    assert all(item.confidence < 1.0 for item in frameworks)


def test_l_ordre_des_frameworks_est_stable():
    """Deux index identiques produisent deux listes identiques."""
    manifests = [
        ManifestEvidence(
            path="package.json", dependency_names=["express", "react", "vue"]
        )
    ]
    premier = discovery.detect_frameworks(manifests, [])
    second = discovery.detect_frameworks(manifests, [])
    assert [item.framework for item in premier] == [
        item.framework for item in second
    ]


# --------------------------------------------------------------------------
# Types de projet — les cinq cas demandes
# --------------------------------------------------------------------------


def build_types(paths, dependencies_by_manifest=None):
    """Raccourci : chemins + dependances -> types de projet."""
    classified = classify(*paths)
    manifests = [
        ManifestEvidence(path=path, dependency_names=names)
        for path, names in (dependencies_by_manifest or {}).items()
    ]
    languages = discovery.detect_languages(classified)
    frameworks = discovery.detect_frameworks(manifests, classified)
    return discovery.detect_project_types(languages, frameworks, classified)


def test_projet_python():
    types = build_types(
        ["src/app.py", "src/models.py", "requirements.txt"],
        {"requirements.txt": ["requests", "click"]},
    )
    assert "Python application" in types
    assert "Frontend" not in types


def test_projet_node_typescript():
    types = build_types(
        ["src/index.ts", "src/util.ts", "package.json", "tsconfig.json"],
        {"package.json": ["typescript", "zod"]},
    )
    assert "Node.js / web application" in types


def test_projet_react():
    types = build_types(
        ["src/App.tsx", "src/index.tsx", "package.json"],
        {"package.json": ["react", "react-dom"]},
    )
    assert "Frontend" in types
    assert "Backend" not in types
    assert "Full-stack" not in types


def test_projet_fastapi():
    types = build_types(
        ["app/main.py", "app/routes.py", "requirements.txt"],
        {"requirements.txt": ["fastapi", "uvicorn"]},
    )
    assert "Backend" in types
    assert "Python application" in types
    assert "Frontend" not in types


def test_projet_full_stack():
    """Frontend et backend a la fois : les trois etiquettes, pas une seule.

    Forcer ce projet dans une case perdrait l'information qui compte pour
    la suite — quelles surfaces analyser.
    """
    types = build_types(
        [
            "frontend/src/App.tsx",
            "frontend/package.json",
            "backend/app/main.py",
            "backend/requirements.txt",
        ],
        {
            "frontend/package.json": ["react", "react-dom"],
            "backend/requirements.txt": ["fastapi"],
        },
    )
    assert "Full-stack" in types
    assert "Frontend" in types
    assert "Backend" in types


def test_projet_inconnu():
    """Dire « inconnu » plutot que deviner.

    Un type invente orienterait a tort toutes les phases suivantes.
    """
    assert build_types(["README.md", "LICENSE", "notes.txt"]) == ["Unknown"]


def test_projet_vide():
    assert build_types([]) == ["Unknown"]


def test_monorepo_detecte_par_manifestes_imbriques():
    types = build_types(
        [
            "package.json",
            "packages/api/package.json",
            "packages/web/package.json",
            "packages/api/src/index.ts",
        ]
    )
    assert "Monorepo" in types


def test_un_seul_manifeste_a_la_racine_n_est_pas_un_monorepo():
    types = build_types(["package.json", "src/index.ts"])
    assert "Monorepo" not in types


def test_un_projet_conteneurise_est_signale():
    types = build_types(["Dockerfile", "src/app.py"])
    assert "Containerised / infrastructure-as-code" in types


def test_les_types_ne_contiennent_aucun_doublon():
    types = build_types(
        ["src/App.tsx", "src/api.ts", "package.json", "Dockerfile"],
        {"package.json": ["react", "express"]},
    )
    assert len(types) == len(set(types))


# --------------------------------------------------------------------------
# Statistiques et troncature
# --------------------------------------------------------------------------


def test_les_statistiques_comptent_par_nature():
    classified = classify(
        "src/a.py",
        "src/b.py",
        "tests/test_a.py",
        "package.json",
        "Dockerfile",
        "tsconfig.json",
        ".env",
        "README.md",
    )
    stats = discovery.statistics(classified, discovered_count=8, truncated=False)

    assert stats.indexed == 8
    assert stats.source == 2
    assert stats.tests == 1
    assert stats.manifests == 1
    # config (tsconfig) + infra (Dockerfile)
    assert stats.configuration == 2
    assert stats.sensitive == 1
    assert stats.truncated is False


def test_une_troncature_est_visible_dans_les_statistiques():
    """`discovered` superieur a `indexed`, et le drapeau l'explique.

    Afficher une couverture partielle comme complete serait un mensonge de
    securite.
    """
    stats = discovery.statistics(
        classify("a.py"), discovered_count=50_000, truncated=True
    )
    assert stats.discovered == 50_000
    assert stats.indexed == 1
    assert stats.truncated is True


def test_discovered_n_est_jamais_inferieur_a_indexed():
    """Un compteur incoherent transmis par le client est corrige."""
    stats = discovery.statistics(
        classify("a.py", "b.py"), discovered_count=0, truncated=False
    )
    assert stats.discovered == 2


# --------------------------------------------------------------------------
# Determinisme
# --------------------------------------------------------------------------


def test_deux_fois_le_meme_index_donne_le_meme_resultat():
    """Sans determinisme, le contexte n'est pas comparable d'une session
    a l'autre — et toute la phase 1 perd son interet."""
    paths = ("src/App.tsx", "backend/app/main.py", "package.json", ".env")
    manifests = [
        ManifestEvidence(path="package.json", dependency_names=["react", "express"])
    ]

    def run():
        classified = discovery.classify_index(index(*paths))
        languages = discovery.detect_languages(classified)
        frameworks = discovery.detect_frameworks(manifests, classified)
        return (
            [item.model_dump() for item in classified],
            [item.model_dump() for item in languages],
            [item.model_dump() for item in frameworks],
            discovery.detect_project_types(languages, frameworks, classified),
        )

    assert run() == run()


# --------------------------------------------------------------------------
# Contrat IA : la frontiere, verifiee
# --------------------------------------------------------------------------


def test_le_contexte_ia_ne_contient_ni_chemin_sensible_ni_identifiant_interne():
    """La projection destinee a un futur modele est verifiee, pas promise.

    Trois choses ne doivent pas s'y trouver : les chemins des fichiers
    sensibles (qui en feraient une carte des fichiers a lire), le
    `root_hash` (identifiant interne sans valeur pour un modele) et l'hote
    du remote Git.
    """
    context = ProjectSecurityContext(
        project_uid="uid-1",
        project_name="MonApplication",
        root_hash="a" * 64,
        security_sensitive_files=[
            ClassifiedFile(
                path="backend/.env",
                kind="sensitive",
                type="environment-secrets",
                reason="peut contenir des identifiants",
            )
        ],
        git_repository_detected=True,
        git_remote_host="github.com",
    )

    ai = build_ai_project_context(context)
    serialise = ai.model_dump_json()

    assert "backend/.env" not in serialise
    assert "a" * 64 not in serialise
    assert "github.com" not in serialise

    # Ce qui traverse : le nombre, pas les chemins.
    assert ai.sensitive_file_count == 0  # aucun fichier dans les statistiques
    assert ai.git_repository_detected is True
    assert ai.project_name == "MonApplication"


def test_le_contexte_ia_transmet_le_nombre_de_fichiers_sensibles():
    """Le modele peut dire « 3 fichiers sensibles » sans savoir lesquels."""
    context = ProjectSecurityContext(
        project_uid="uid-1",
        project_name="App",
        root_hash="b" * 64,
    )
    context.file_statistics.sensitive = 3
    assert build_ai_project_context(context).sensitive_file_count == 3


def test_le_contexte_ia_transmet_la_troncature():
    """Une couverture partielle doit etre dite au modele comme a l'humain.

    Sans elle, une reponse rassurante serait fausse.
    """
    context = ProjectSecurityContext(
        project_uid="uid-1", project_name="App", root_hash="c" * 64
    )
    context.file_statistics.truncated = True
    assert build_ai_project_context(context).index_truncated is True


def test_le_contexte_ia_n_expose_que_des_champs_decides():
    """Un champ ajoute au contexte n'atteint pas le prompt par accident."""
    from app.project.ai_contract import AiProjectContext

    assert set(AiProjectContext.model_fields) == {
        "project_name",
        "project_types",
        "primary_language",
        "language_shares",
        "frameworks",
        "indexed_file_count",
        "source_file_count",
        "sensitive_file_count",
        "index_truncated",
        "git_repository_detected",
    }
