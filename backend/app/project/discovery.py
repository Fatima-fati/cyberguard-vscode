"""Classement deterministe d'un index de projet.

Aucun appel reseau, aucun modele, aucune lecture de fichier : ce module ne
travaille que sur des chemins et des noms de dependances. Deux fois le
meme index produit exactement le meme resultat — c'est ce qui rend le
contexte comparable d'une session a l'autre.

Trois questions, trois etapes :

    chemins        -> langue de chaque fichier, nature de chaque fichier
    manifestes     -> frameworks, avec leur preuve
    les deux       -> types de projet

Regle tenue partout : **rien n'est affirme sans preuve.** Un framework
n'est detecte que si une dependance declaree ou un fichier de
configuration l'atteste, et la preuve voyage avec la detection jusqu'a
l'interface.
"""

from typing import Iterable, Optional

from app.project.schemas import (
    ClassifiedFile,
    DetectedFramework,
    DetectedLanguage,
    FileStatistics,
    FileKind,
    IndexedFile,
    ManifestEvidence,
)

# --------------------------------------------------------------------------
# Langages
# --------------------------------------------------------------------------

# Extension -> langage. Volontairement limite aux langages que le projet
# nomme : deviner « ce langage est probablement du C » a partir d'un `.h`
# ambigu n'apporte rien et introduit du faux.
_LANGUAGE_BY_EXTENSION: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".java": "java",
    ".php": "php",
    ".go": "go",
    ".cs": "csharp",
    ".rb": "ruby",
    ".sql": "sql",
}

# Langages pour lesquels le moteur de regles a effectivement des regles.
# Doit refleter `app.code.rules`, pas une ambition : une extension qui
# annonce « Java couvert » alors qu'aucune regle Java n'existe induit
# l'utilisateur en erreur sur sa propre exposition.
ANALYSIS_SUPPORTED_LANGUAGES: frozenset[str] = frozenset(
    {"python", "javascript", "typescript", "java", "php"}
)


def language_for_path(path: str) -> Optional[str]:
    """Langage d'un fichier, d'apres son extension. `None` si inconnu."""
    lowered = path.lower()
    for extension, language in _LANGUAGE_BY_EXTENSION.items():
        if lowered.endswith(extension):
            return language
    return None


# --------------------------------------------------------------------------
# Nature des fichiers
# --------------------------------------------------------------------------

# Manifestes de dependances, par ecosysteme. La cle est le nom de fichier
# en minuscules ; `*.csproj` est traite a part (motif d'extension).
_MANIFESTS: dict[str, tuple[str, str]] = {
    "package.json": ("npm", "npm-manifest"),
    "package-lock.json": ("npm", "npm-lockfile"),
    "yarn.lock": ("npm", "npm-lockfile"),
    "pnpm-lock.yaml": ("npm", "npm-lockfile"),
    "requirements.txt": ("pypi", "pip-requirements"),
    "requirements-dev.txt": ("pypi", "pip-requirements"),
    "pyproject.toml": ("pypi", "python-project"),
    "pipfile": ("pypi", "pipenv-manifest"),
    "poetry.lock": ("pypi", "python-lockfile"),
    "setup.py": ("pypi", "python-setup"),
    "pom.xml": ("maven", "maven-manifest"),
    "build.gradle": ("maven", "gradle-manifest"),
    "build.gradle.kts": ("maven", "gradle-manifest"),
    "composer.json": ("composer", "composer-manifest"),
    "composer.lock": ("composer", "composer-lockfile"),
    "go.mod": ("go", "go-manifest"),
    "go.sum": ("go", "go-lockfile"),
    "gemfile": ("rubygems", "bundler-manifest"),
    "gemfile.lock": ("rubygems", "bundler-lockfile"),
    "cargo.toml": ("cargo", "cargo-manifest"),
}

# Fichiers de configuration et d'infrastructure, par nom exact.
_CONFIG_BY_NAME: dict[str, tuple[FileKind, str, str]] = {
    "dockerfile": ("infra", "docker", "definit une image de conteneur"),
    "docker-compose.yml": ("infra", "docker-compose", "orchestre des conteneurs"),
    "docker-compose.yaml": ("infra", "docker-compose", "orchestre des conteneurs"),
    ".dockerignore": ("infra", "docker-ignore", "perimetre du contexte de build"),
    "tsconfig.json": ("config", "typescript-config", "configuration du compilateur"),
    "jsconfig.json": ("config", "javascript-config", "configuration du projet"),
    ".gitignore": ("config", "git-ignore", "fichiers exclus du depot"),
    ".gitattributes": ("config", "git-attributes", "traitement des fichiers par Git"),
    ".editorconfig": ("config", "editor-config", "conventions d'edition"),
    ".eslintrc": ("config", "eslint-config", "regles de lint"),
    ".eslintrc.json": ("config", "eslint-config", "regles de lint"),
    ".eslintrc.js": ("config", "eslint-config", "regles de lint"),
    "eslint.config.js": ("config", "eslint-config", "regles de lint"),
    "pytest.ini": ("config", "pytest-config", "configuration des tests"),
    "tox.ini": ("config", "tox-config", "matrice de tests"),
    "setup.cfg": ("config", "python-config", "configuration du paquet"),
    "manage.py": ("config", "django-entrypoint", "point d'entree Django"),
    "artisan": ("config", "laravel-entrypoint", "point d'entree Laravel"),
    "angular.json": ("config", "angular-config", "configuration Angular"),
    "nest-cli.json": ("config", "nestjs-config", "configuration NestJS"),
    "next.config.js": ("config", "nextjs-config", "configuration Next.js"),
    "nuxt.config.ts": ("config", "nuxt-config", "configuration Nuxt"),
    "svelte.config.js": ("config", "svelte-config", "configuration Svelte"),
    "web.config": ("config", "aspnet-config", "configuration IIS / ASP.NET"),
    "appsettings.json": ("config", "aspnet-settings", "reglages ASP.NET"),
    "application.properties": ("config", "spring-config", "reglages Spring"),
    "application.yml": ("config", "spring-config", "reglages Spring"),
    "makefile": ("config", "make", "cibles de build"),
    "procfile": ("config", "procfile", "commandes de demarrage"),
}

# Fichiers de configuration reconnus par prefixe de nom (variantes de
# suffixe : `vite.config.ts`, `vite.config.mjs`…).
_CONFIG_BY_PREFIX: tuple[tuple[str, FileKind, str, str], ...] = (
    ("vite.config.", "config", "vite-config", "configuration du bundler"),
    ("webpack.config.", "config", "webpack-config", "configuration du bundler"),
    ("rollup.config.", "config", "rollup-config", "configuration du bundler"),
    ("babel.config.", "config", "babel-config", "configuration du transpileur"),
    ("jest.config.", "config", "jest-config", "configuration des tests"),
    ("vitest.config.", "config", "vitest-config", "configuration des tests"),
    ("tailwind.config.", "config", "tailwind-config", "configuration CSS"),
)

# Extensions d'infrastructure.
_INFRA_EXTENSIONS: tuple[tuple[str, str, str], ...] = (
    (".tf", "terraform", "decrit de l'infrastructure"),
    (".tfvars", "terraform-vars", "variables d'infrastructure"),
)

# Fichiers sensibles : ils ne sont **jamais lus**. Le motif suffit a les
# classer, et c'est tout ce qu'on veut en savoir a cette phase.
#
# Le classement porte sur le nom parce que c'est la seule information
# disponible sans ouvrir le fichier. Cette limite est reelle et assumee :
# un `config.local.js` qui contiendrait une cle privee n'apparaitrait pas
# ici. La detection de secrets par contenu appartient a une phase
# ulterieure et se fera cote extension, sans transmettre la valeur.
_SENSITIVE_SUFFIXES: tuple[tuple[str, str, str], ...] = (
    (".pem", "private-key-or-certificate", "peut contenir une cle privee"),
    (".key", "private-key", "peut contenir une cle privee"),
    (".p12", "keystore", "conteneur de cles et certificats"),
    (".pfx", "keystore", "conteneur de cles et certificats"),
    (".jks", "keystore", "magasin de cles Java"),
    (".keystore", "keystore", "magasin de cles"),
    (".ppk", "private-key", "cle privee PuTTY"),
    (".asc", "pgp-key", "peut contenir une cle PGP"),
)

_SENSITIVE_NAMES: dict[str, tuple[str, str]] = {
    ".env": ("environment-secrets", "peut contenir des identifiants"),
    ".npmrc": ("registry-credentials", "peut contenir un jeton de depot"),
    ".pypirc": ("registry-credentials", "peut contenir un jeton de depot"),
    ".netrc": ("host-credentials", "identifiants par hote"),
    ".htpasswd": ("password-file", "empreintes de mots de passe"),
    "credentials": ("credentials", "identifiants"),
    "id_rsa": ("ssh-private-key", "cle privee SSH"),
    "id_dsa": ("ssh-private-key", "cle privee SSH"),
    "id_ecdsa": ("ssh-private-key", "cle privee SSH"),
    "id_ed25519": ("ssh-private-key", "cle privee SSH"),
}

_SENSITIVE_PREFIXES: tuple[tuple[str, str, str], ...] = (
    (".env.", "environment-secrets", "peut contenir des identifiants"),
    ("credentials.", "credentials", "identifiants"),
    ("secrets.", "secrets", "peut contenir des secrets"),
    ("secret.", "secrets", "peut contenir des secrets"),
)

# `.env.example` et consorts sont des **modeles** : leur raison d'etre est
# de ne porter aucune valeur. Les classer « sensibles » banaliserait la
# liste, et une liste banalisee n'est plus lue.
_SENSITIVE_EXEMPT_SUFFIXES: tuple[str, ...] = (
    ".example",
    ".sample",
    ".template",
    ".dist",
)

# Chemins de tests. Reprend l'esprit de `app.code.risk` : un finding dans
# un test ne porte pas le meme risque qu'en production.
_TEST_SEGMENTS: frozenset[str] = frozenset(
    {"test", "tests", "spec", "specs", "__tests__", "testing", "e2e", "fixtures"}
)

_TEST_NAME_MARKERS: tuple[str, ...] = (
    "test_",
    "_test.",
    ".test.",
    ".spec.",
    "spec_",
    "_spec.",
)

# Fichiers importants pour la securite d'un projet, sans etre ni un
# manifeste ni une configuration technique.
_IMPORTANT_BY_NAME: dict[str, tuple[str, str]] = {
    "readme.md": ("documentation", "documentation d'entree du projet"),
    "security.md": ("security-policy", "politique de securite declaree"),
    "license": ("license", "conditions de reutilisation"),
    "license.md": ("license", "conditions de reutilisation"),
    "codeowners": ("code-owners", "responsables du code"),
}


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _is_sensitive_exempt(name: str) -> bool:
    return any(name.endswith(suffix) for suffix in _SENSITIVE_EXEMPT_SUFFIXES)


def _looks_like_test(path: str) -> bool:
    lowered = path.lower()
    segments = lowered.split("/")
    if any(segment in _TEST_SEGMENTS for segment in segments[:-1]):
        return True
    name = segments[-1]
    return any(marker in name for marker in _TEST_NAME_MARKERS)


def classify_path(path: str) -> ClassifiedFile:
    """Nature d'un fichier, d'apres son chemin seul.

    L'ordre des controles porte une decision : **le classement sensible
    passe en premier.** Un `.env` doit etre reconnu comme sensible avant
    d'etre vu comme une configuration, sinon il se retrouverait dans une
    liste ou l'on s'autorise a lire.
    """
    name = _basename(path).lower()
    lowered = path.lower()

    # 1. Sensible — avant tout le reste.
    if not _is_sensitive_exempt(name):
        if name in _SENSITIVE_NAMES:
            kind, reason = _SENSITIVE_NAMES[name]
            return ClassifiedFile(path=path, kind="sensitive", type=kind, reason=reason)

        for prefix, kind, reason in _SENSITIVE_PREFIXES:
            if name.startswith(prefix):
                return ClassifiedFile(
                    path=path, kind="sensitive", type=kind, reason=reason
                )

        for suffix, kind, reason in _SENSITIVE_SUFFIXES:
            if name.endswith(suffix):
                return ClassifiedFile(
                    path=path, kind="sensitive", type=kind, reason=reason
                )

    # 2. Manifeste de dependances.
    if name in _MANIFESTS:
        _, manifest_type = _MANIFESTS[name]
        return ClassifiedFile(
            path=path,
            kind="manifest",
            type=manifest_type,
            reason="declare les dependances du projet",
        )

    if name.endswith(".csproj") or name.endswith(".fsproj"):
        return ClassifiedFile(
            path=path,
            kind="manifest",
            type="dotnet-manifest",
            reason="declare les dependances du projet",
        )

    # 3. Infrastructure et configuration.
    if name in _CONFIG_BY_NAME:
        kind, config_type, reason = _CONFIG_BY_NAME[name]
        return ClassifiedFile(path=path, kind=kind, type=config_type, reason=reason)

    for prefix, kind, config_type, reason in _CONFIG_BY_PREFIX:
        if name.startswith(prefix):
            return ClassifiedFile(path=path, kind=kind, type=config_type, reason=reason)

    for suffix, config_type, reason in _INFRA_EXTENSIONS:
        if name.endswith(suffix):
            return ClassifiedFile(
                path=path, kind="infra", type=config_type, reason=reason
            )

    # Workflows CI : leur emplacement suffit a les identifier.
    if lowered.startswith(".github/workflows/") and (
        name.endswith(".yml") or name.endswith(".yaml")
    ):
        return ClassifiedFile(
            path=path,
            kind="infra",
            type="github-workflow",
            reason="automatisation d'integration continue",
        )

    # 4. Tests — avant « source », pour qu'un test ne soit pas compte
    #    comme du code de production.
    if _looks_like_test(path):
        return ClassifiedFile(
            path=path, kind="test", type="test", reason="code de test"
        )

    # 5. Source.
    language = language_for_path(path)
    if language:
        return ClassifiedFile(
            path=path, kind="source", type=language, reason="code source"
        )

    # 6. Documentation et divers notables.
    if name in _IMPORTANT_BY_NAME:
        doc_type, reason = _IMPORTANT_BY_NAME[name]
        return ClassifiedFile(
            path=path, kind="documentation", type=doc_type, reason=reason
        )

    return ClassifiedFile(path=path, kind="other", type="other", reason="")


# --------------------------------------------------------------------------
# Frameworks
# --------------------------------------------------------------------------

# Nom de dependance -> framework. Une correspondance exacte, jamais une
# sous-chaine : `react-scripts` ne prouve pas React, et `flask-cors` seul
# ne prouve pas une application Flask.
_FRAMEWORK_BY_DEPENDENCY: dict[str, str] = {
    # JavaScript / TypeScript
    "react": "React",
    "react-dom": "React",
    "@angular/core": "Angular",
    "vue": "Vue",
    "svelte": "Svelte",
    "next": "Next.js",
    "nuxt": "Nuxt",
    "express": "Express",
    "@nestjs/core": "NestJS",
    "koa": "Koa",
    "fastify": "Fastify",
    "hapi": "hapi",
    "@hapi/hapi": "hapi",
    # Python
    "fastapi": "FastAPI",
    "flask": "Flask",
    "django": "Django",
    "starlette": "Starlette",
    "tornado": "Tornado",
    "aiohttp": "aiohttp",
    "pyramid": "Pyramid",
    # Java
    "spring-boot": "Spring Boot",
    "spring-boot-starter": "Spring Boot",
    "spring-boot-starter-web": "Spring Boot",
    "spring-core": "Spring",
    "spring-web": "Spring",
    "quarkus": "Quarkus",
    "micronaut": "Micronaut",
    # PHP
    "laravel/framework": "Laravel",
    "symfony/symfony": "Symfony",
    "symfony/framework-bundle": "Symfony",
    "slim/slim": "Slim",
    # Ruby
    "rails": "Ruby on Rails",
    "sinatra": "Sinatra",
    # Go
    "github.com/gin-gonic/gin": "Gin",
    "github.com/labstack/echo": "Echo",
    "github.com/gofiber/fiber": "Fiber",
    # .NET
    "microsoft.aspnetcore.app": "ASP.NET Core",
    "microsoft.aspnetcore": "ASP.NET Core",
}

# Fichier de configuration -> framework. Une preuve d'une autre nature,
# plus faible qu'une dependance declaree mais souvent decisive.
_FRAMEWORK_BY_CONFIG_TYPE: dict[str, str] = {
    "angular-config": "Angular",
    "nestjs-config": "NestJS",
    "nextjs-config": "Next.js",
    "nuxt-config": "Nuxt",
    "svelte-config": "Svelte",
    "django-entrypoint": "Django",
    "laravel-entrypoint": "Laravel",
    "spring-config": "Spring",
    "aspnet-config": "ASP.NET",
    "aspnet-settings": "ASP.NET",
}


def detect_frameworks(
    manifests: Iterable[ManifestEvidence],
    classified: Iterable[ClassifiedFile],
) -> list[DetectedFramework]:
    """Frameworks attestes par une dependance declaree ou un fichier dedie.

    Une dependance declaree vaut 0,9 : le projet l'a ecrite lui-meme. Un
    fichier de configuration vaut 0,7 : il peut survivre a la suppression
    du framework. Aucune des deux ne vaut 1,0 — un manifeste peut declarer
    une dependance que le code n'utilise plus, et cette phase ne lit pas
    le code.
    """
    found: dict[str, DetectedFramework] = {}

    for manifest in manifests:
        for name in manifest.dependency_names:
            framework = _FRAMEWORK_BY_DEPENDENCY.get(name.lower())
            if framework is None:
                continue
            current = found.get(framework)
            if current is not None and current.confidence >= 0.9:
                continue
            found[framework] = DetectedFramework(
                framework=framework,
                evidence=f"dependance « {name} » declaree",
                source=manifest.path,
                confidence=0.9,
            )

    for entry in classified:
        framework = _FRAMEWORK_BY_CONFIG_TYPE.get(entry.type)
        if framework is None or framework in found:
            continue
        found[framework] = DetectedFramework(
            framework=framework,
            evidence="fichier de configuration dedie",
            source=entry.path,
            confidence=0.7,
        )

    # Ordre stable : la confiance d'abord, le nom ensuite. Deux index
    # identiques doivent produire deux listes identiques.
    return sorted(found.values(), key=lambda item: (-item.confidence, item.framework))


# --------------------------------------------------------------------------
# Langages constates
# --------------------------------------------------------------------------


def detect_languages(classified: Iterable[ClassifiedFile]) -> list[DetectedLanguage]:
    """Langages presents, d'apres les fichiers source et de test reels.

    Les fichiers `other` sont exclus : compter un `.md` comme un langage
    gonflerait les proportions sans rien dire du code.
    """
    counts: dict[str, int] = {}
    for entry in classified:
        if entry.kind not in {"source", "test"}:
            continue
        language = language_for_path(entry.path)
        if language is None:
            continue
        counts[language] = counts.get(language, 0) + 1

    total = sum(counts.values())
    languages = [
        DetectedLanguage(
            language=language,
            file_count=count,
            share=round(count * 100 / total) if total else 0,
            analysis_supported=language in ANALYSIS_SUPPORTED_LANGUAGES,
        )
        for language, count in counts.items()
    ]
    return sorted(languages, key=lambda item: (-item.file_count, item.language))


# --------------------------------------------------------------------------
# Types de projet
# --------------------------------------------------------------------------

_FRONTEND_FRAMEWORKS: frozenset[str] = frozenset(
    {"React", "Angular", "Vue", "Svelte", "Next.js", "Nuxt"}
)

_BACKEND_FRAMEWORKS: frozenset[str] = frozenset(
    {
        "FastAPI",
        "Flask",
        "Django",
        "Starlette",
        "Tornado",
        "aiohttp",
        "Pyramid",
        "Express",
        "NestJS",
        "Koa",
        "Fastify",
        "hapi",
        "Spring",
        "Spring Boot",
        "Quarkus",
        "Micronaut",
        "Laravel",
        "Symfony",
        "Slim",
        "Ruby on Rails",
        "Sinatra",
        "Gin",
        "Echo",
        "Fiber",
        "ASP.NET",
        "ASP.NET Core",
    }
)


def detect_project_types(
    languages: list[DetectedLanguage],
    frameworks: list[DetectedFramework],
    classified: list[ClassifiedFile],
) -> list[str]:
    """Caracteristiques du projet. Plusieurs peuvent tenir a la fois.

    Volontairement une **liste** et non une categorie unique : un dossier
    qui contient un frontend React et un backend FastAPI est les deux, et
    le forcer dans une case perdrait l'information qui compte pour la
    suite (quelles surfaces analyser).
    """
    names = {item.framework for item in frameworks}
    types: list[str] = []

    has_frontend = bool(names & _FRONTEND_FRAMEWORKS)
    has_backend = bool(names & _BACKEND_FRAMEWORKS)

    if has_frontend and has_backend:
        types.append("Full-stack")
    if has_frontend:
        types.append("Frontend")
    if has_backend:
        types.append("Backend")

    # Langage dominant : une caracteristique de plus, pas une categorie
    # exclusive.
    by_language = {item.language: item for item in languages}
    if "python" in by_language:
        types.append("Python application")
    if "typescript" in by_language or "javascript" in by_language:
        types.append("Node.js / web application")
    if "java" in by_language:
        types.append("Java application")
    if "csharp" in by_language:
        types.append(".NET application")
    if "php" in by_language:
        types.append("PHP application")
    if "go" in by_language:
        types.append("Go application")
    if "ruby" in by_language:
        types.append("Ruby application")

    manifest_paths = [
        entry.path for entry in classified if entry.kind == "manifest"
    ]
    # Un manifeste dans un sous-dossier, en plus de celui de la racine :
    # signature d'un depot a plusieurs paquets.
    nested_manifests = [path for path in manifest_paths if "/" in path]
    root_manifests = [path for path in manifest_paths if "/" not in path]
    if nested_manifests and (root_manifests or len(nested_manifests) > 1):
        types.append("Monorepo")

    if any(entry.kind == "infra" for entry in classified):
        types.append("Containerised / infrastructure-as-code")

    if not types:
        # Dire « inconnu » plutot que deviner : un type invente
        # orienterait a tort les phases suivantes.
        types.append("Unknown")

    # Doublons ecartes en conservant l'ordre d'apparition.
    seen: set[str] = set()
    ordered: list[str] = []
    for item in types:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


# --------------------------------------------------------------------------
# Assemblage
# --------------------------------------------------------------------------


def classify_index(files: Iterable[IndexedFile]) -> list[ClassifiedFile]:
    """Classe tout l'index. Ordre d'entree conserve."""
    return [classify_path(entry.path) for entry in files]


def statistics(
    classified: list[ClassifiedFile],
    discovered_count: int,
    truncated: bool,
) -> FileStatistics:
    """Volumes par nature. `discovered` peut depasser `indexed`.

    C'est precisement l'interet de garder les deux : quand la decouverte a
    ete plafonnee, la difference est visible et le drapeau `truncated`
    l'explique.
    """
    def count(kind: FileKind) -> int:
        return sum(1 for entry in classified if entry.kind == kind)

    indexed = len(classified)
    return FileStatistics(
        discovered=max(discovered_count, indexed),
        indexed=indexed,
        source=count("source"),
        manifests=count("manifest"),
        configuration=count("config") + count("infra"),
        tests=count("test"),
        sensitive=count("sensitive"),
        truncated=truncated,
    )


def primary_language(languages: list[DetectedLanguage]) -> Optional[str]:
    """Langage le plus represente, ou `None` si aucun fichier source."""
    return languages[0].language if languages else None
