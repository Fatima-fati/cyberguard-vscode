# CyberGuard VS Code

Une extension de sécurité pour Visual Studio Code qui intègre la détection,
l'analyse et la surveillance de sécurité directement dans l'environnement de
développement.

---

## Vue d'ensemble

Les problèmes de sécurité sont moins coûteux à corriger lorsqu'ils sont
détectés au moment où le code est écrit. En pratique, ils sont souvent
découverts bien plus tard, lors d'une revue de code, d'un pipeline CI ou
d'un test d'intrusion, alors que le développeur est déjà passé à autre
chose. Une clé d'API écrite en dur, une requête SQL construite par
concaténation ou une dépendance vulnérable peuvent traverser plusieurs
commits avant que quelqu'un ne s'en aperçoive.

**CyberGuard VS Code** raccourcit cette boucle en rapprochant la sécurité du
développeur. L'extension surveille le projet pendant le travail, analyse les
fichiers au fil de leurs modifications et présente les findings là où se
trouve le code : soulignés dans l'éditeur, listés dans le panneau Problems
et regroupés dans une vue Security dédiée. Chaque finding indique sa
gravité, une explication, l'impact potentiel et une recommandation.

Le projet se compose de deux parties complémentaires :

- **L'extension VS Code** (TypeScript) surveille le workspace et exécute
  les analyses qui doivent rester sur le poste du développeur : détection
  des secrets, inventaire des dépendances, analyse des routes d'API. Elle
  présente l'ensemble des résultats dans l'éditeur.
- **Le backend de sécurité** (Python, FastAPI) expose une API HTTP locale.
  Il détient les règles d'analyse du code, stocke les findings, compare
  les dépendances à une base publique de vulnérabilités et, lorsqu'il est
  configuré, fournit l'assistance IA.

La détection est **déterministe** : les findings proviennent de règles
explicites et non d'un modèle de langage. L'assistant IA, optionnel,
intervient uniquement pour aider le développeur à comprendre et à corriger
les problèmes détectés. Il ne crée, ne supprime et ne modifie aucun
finding.

## Fonctionnalités principales

### Sécurité du code

- Analyse par règles des fichiers **Python, JavaScript, TypeScript (JSX/TSX
  compris), PHP et Java**.
- 19 règles couvrant l'injection SQL, l'injection de commandes, le XSS, les
  secrets écrits en dur, le path traversal, l'usage dangereux d'`eval`, la
  désérialisation non sûre, la cryptographie faible, l'aléatoire non sûr,
  la configuration non sécurisée, le SSRF, le XXE et les redirections
  ouvertes.
- Chaque finding comporte une gravité (`CRITICAL`, `HIGH`, `MEDIUM`,
  `LOW`), une référence CWE et OWASP, une explication, l'impact potentiel
  et des recommandations.
- Diagnostics VS Code natifs : code souligné, panneau Problems et survol
  détaillé.
- Corrections mécaniques pour certaines règles, appliquées uniquement après
  confirmation explicite et annulables avec `Ctrl+Z`.

### Détection des secrets

- Détection locale des identifiants exposés. Les types pris en charge
  comprennent :
  - clés d'API : OpenAI, Anthropic, AWS, Google, Stripe, SendGrid, Mailgun ;
  - jetons : GitHub, GitLab, Slack, npm ;
  - webhooks : Slack, Discord ;
  - clés privées, JWT et secrets de signature JWT, secrets clients OAuth ;
  - URL de bases de données et chaînes de connexion, en-têtes
    `Bearer`/`Basic` ;
  - clés de stockage Azure, comptes de service Google Cloud et mots de
    passe écrits en dur.
- **Redaction** : la valeur d'un secret ne quitte jamais le poste. Seule
  une forme masquée de la preuve (par exemple `sk-proj-********`) est
  transmise, et le backend la masque à nouveau avant de la stocker.
- **Gestion des faux positifs** : les placeholders et les lectures de
  variables d'environnement sont écartés. Les correspondances trouvées dans
  des fichiers de test ou d'exemple, ainsi que les valeurs de faible
  entropie, voient leur gravité abaissée au lieu d'être masquées.
- Les fichiers classés sensibles (`.env`, clés privées, certificats,
  fichiers d'identifiants) sont signalés par leur chemin et ne sont
  **jamais lus**.

### Surveillance du projet

- Surveillance continue du workspace ouvert au moyen d'un
  `FileSystemWatcher` VS Code.
- Seuls les fichiers réellement modifiés sont analysés à nouveau : la
  taille, la date de modification et une empreinte SHA-256 sont comparées
  au préalable. Un fichier réécrit à l'identique ne déclenche donc rien.
- Les modifications effectuées **en dehors de l'éditeur** sont également
  détectées, par exemple après un `git pull`, sans sauvegarde ni scan
  manuel (voir [Workflow de sécurité](#workflow-de-sécurité)).
- Une file d'analyse dédiée gère l'anti-rebond, le dédoublonnage, la
  priorité donnée au fichier qui vient d'être enregistré, la concurrence
  bornée et l'annulation.
- L'analyse à la sauvegarde et les commandes à la demande (*Scan Current
  File*, *Scan Workspace*, *Scan Project Security*) restent disponibles.

### Sécurité des dépendances et des API

- **Inventaire des dépendances** à partir des manifestes et des fichiers de
  verrouillage. Écosystèmes pris en charge : npm, PyPI, Maven/Gradle,
  Composer, Go, RubyGems et Cargo. Rien n'est installé ni exécuté : seuls
  des fichiers texte sont lus.
- **Vulnérabilités connues** : les versions figées sont comparées à la base
  publique [OSV](https://osv.dev), uniquement par l'intermédiaire du
  backend. Une dépendance qui ne peut pas être vérifiée est signalée comme
  *non vérifiée*, jamais comme sûre.
- **Sécurité des API** : analyse statique des routes déclarées pour
  Express, NestJS, FastAPI, Flask, Django, Spring, Laravel et ASP.NET.
  Elle couvre :
  - les endpoints modifiant un état sans authentification apparente ;
  - les routes sensibles sans contrôle d'autorisation ;
  - les configurations CORS permissives ;
  - la vérification TLS désactivée et les appels en HTTP non chiffré ;
  - le mode débogage et les endpoints de diagnostic exposés ;
  - les identifiants intégrés dans des en-têtes ou des URL.

### Sécurité Git

- Intégration avec l'extension Git intégrée à VS Code. CyberGuard
  n'exécute aucune commande `git`.
- *Scan Git Changes* analyse les fichiers modifiés et **attribue** chaque
  finding : introduit par le changement en cours, ou déjà présent.
- *Check Changes Before Push* évalue le changement selon une politique
  configurable (`off`, `warn`, `block`). Seuls les problèmes `CRITICAL` ou
  `HIGH` **introduits** par le changement sont pris en compte.
- Les changements volumineux basculent dans un mode réduit, annoncé
  explicitement, et la vérification s'exécute dans un budget de temps : en
  cas de dépassement, le résultat est présenté comme *non vérifié*.

### Assistant de sécurité basé sur l'IA

L'assistant IA est optionnel et s'exécute côté backend : l'extension ne
contacte jamais directement un fournisseur d'IA. Il permet de :

- **expliquer** un finding dans son contexte (*Analyze with AI*) ;
- **résumer** les findings du projet (*Summarize Findings with AI*) ;
- **répondre aux questions** dans un chat de sécurité. La question est
  masquée dans l'extension, puis à nouveau par le backend ;
- **proposer une correction** limitée aux lignes concernées (*Suggest Fix
  with AI*), présentée sous forme de diff. Rien n'est écrit sans
  confirmation. Une fois la correction appliquée, les moteurs
  déterministes analysent à nouveau le fichier et confirment si le
  problème a disparu.

Tout texte produit par l'IA est signalé comme tel. Les fichiers `.env`, les
clés privées, les certificats et les fichiers d'identifiants ne sont
jamais modifiés. Sans clé d'API configurée sur le backend, toutes les
autres fonctionnalités restent identiques.

### Interface VS Code

- **Vue Security** dans la barre d'activité, composée de trois panneaux :
  - *Project* : langages, frameworks, fichiers sensibles, secrets,
    dépendances, vulnérabilités, changements Git et posture de sécurité ;
  - *Risk Overview* : nombre de findings par gravité ;
  - *Findings* : findings regroupés par gravité.
- **Panneau de détail d'un finding** : explication complète, impact,
  facteurs de risque et actions disponibles.
- **Actions rapides** : actions de l'ampoule pour corriger, afficher le
  détail ou écarter un finding comme faux positif.
- **Barre d'état** : synthèse de sécurité courante, état de la
  surveillance et avertissement lorsqu'un backend distant est utilisé.
- **Notifications** : dédoublonnées et regroupées. Une analyse qui révèle
  vingt problèmes produit une seule notification, et non vingt.
- **Panneau IA** : explications, résumés, chat et propositions de
  correction.

### CI Check

Les mêmes moteurs sont disponibles hors de VS Code sous la forme d'une
vérification en ligne de commande (`dist/ci-check.js`). Elle produit un
rapport JSON et un code de sortie qu'un pipeline peut utiliser pour avertir
ou bloquer selon des conditions telles que des findings `CRITICAL`, des
secrets exposés ou des dépendances vulnérables.

## Architecture

```text
┌─────────────────────────────────────┐
│          Visual Studio Code         │
│                                     │
│        Extension CyberGuard         │
│                                     │
│   Surveillance • Diagnostics • UI   │
│   Détection des secrets (locale)    │
│   Inventaire des dépendances        │
│   Règles API • Git • Corrections    │
└──────────────────┬──────────────────┘
                   │ HTTP (jeton local) / SSE
                   ▼
┌─────────────────────────────────────┐
│        Backend de sécurité          │
│                                     │
│   FastAPI • Règles d'analyse        │
│   Stockage des findings (SQLite)    │
│   Contexte projet • Posture / CI    │
│   Authentification • Redaction      │
└─────────┬─────────────────┬─────────┘
          │                 │ optionnel
          ▼                 ▼
   Base de vulnérabilités   API compatible
          OSV                   OpenAI
```

Choix de conception :

- **Priorité au local.** Par défaut, le backend écoute sur `127.0.0.1`.
  L'utilisation d'un backend situé sur une autre machine exige une
  activation explicite dans les paramètres de l'extension, et un
  repository ne peut pas modifier ce paramètre de lui-même.
- **Les secrets restent locaux.** La détection des secrets s'exécute dans
  l'extension ; seule une preuve masquée est transmise.
- **Une source de vérité unique.** Les findings sont stockés par le
  backend puis relus par l'extension. La vue de l'éditeur, le panneau
  Problems et le CI Check affichent donc les mêmes données.
- **API authentifiée.** Les routes protégées exigent un jeton local. Le
  backend le génère dans le profil de l'utilisateur, hors du repository ;
  l'extension le lit et le conserve dans le trousseau du système.
- **Contrat partagé.** `contract/api-contract.json` décrit l'API entre les
  deux parties, et un test de chaque côté en vérifie le respect.

## Stack technologique

| Domaine            | Technologies                                                    |
| ------------------ | --------------------------------------------------------------- |
| Extension          | TypeScript (strict), VS Code Extension API, Node.js, esbuild    |
| Backend            | Python 3.12, FastAPI, Uvicorn, Pydantic, httpx                  |
| Stockage           | SQLite                                                          |
| Données de sécurité | Base de vulnérabilités OSV                                     |
| IA (optionnelle)   | API Chat compatible OpenAI, appelée uniquement par le backend   |
| Tests              | Lanceur de tests intégré à Node.js, pytest                      |

## Structure du projet

```text
cyberguard-vscode/
├── vscode-extension/      extension VS Code (TypeScript)
│   ├── src/               surveillance, analyse, secrets, dépendances,
│   │                      règles API, Git, IA, remédiation, interface
│   ├── test/              tests unitaires (lanceur de tests Node.js)
│   ├── resources/         icônes
│   └── package.json       manifeste, commandes, paramètres, scripts
│
├── backend/               backend de sécurité (FastAPI)
│   ├── app/               routes d'API, règles d'analyse du code,
│   │                      services de sécurité, intégration IA,
│   │                      authentification, stockage
│   ├── tests/             suite pytest
│   ├── .env.example       modèle de configuration (sans secret)
│   └── requirements.txt
│
├── contract/              contrat d'API partagé par les deux parties
├── docs/                  notes de conception : modèle de sécurité,
│                          contexte de projet
├── .gitignore
└── README.md
```

## Installation

### Prérequis

- Visual Studio Code **1.85** ou version ultérieure
- **Node.js 18+** et npm
- **Python 3.12**
- Git

### 1. Cloner le repository

```bash
git clone https://github.com/Fatima-fati/cyberguard-vscode.git
cd cyberguard-vscode
```

### 2. Installer le backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # macOS / Linux: source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt   # Dépendances de test (pytest)
```

### 3. Créer la configuration du backend

```powershell
copy .env.example .env                # macOS / Linux: cp .env.example .env
```

Les valeurs par défaut suffisent pour l'analyse du code, la détection des
secrets et l'analyse des dépendances et des API. Voir
[Configuration](#configuration).

### 4. Installer et compiler l'extension

```powershell
cd ..\vscode-extension
npm ci
npm run compile
```

### 5. Démarrer le backend

```powershell
cd ..\backend
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Pour vérifier que le backend fonctionne :
`http://127.0.0.1:8000/api/code/health` doit renvoyer
`{"status":"ok", ...}`, et la documentation OpenAPI est disponible à
l'adresse `http://127.0.0.1:8000/docs`.

Au premier démarrage, le backend crée sa base SQLite dans `backend/data/`.
Il génère également le jeton d'authentification local dans le profil de
l'utilisateur, où l'extension le récupère automatiquement. Il n'y a rien à
copier.

### 6. Lancer l'extension en mode développement

1. Ouvrir le dossier **`vscode-extension/`** dans VS Code.
2. Appuyer sur **F5**. La configuration de lancement fournie compile
   l'extension et ouvre une seconde fenêtre VS Code dans laquelle
   CyberGuard est chargé.
3. Dans cette fenêtre, ouvrir le projet à analyser.

## Configuration

### Backend (`backend/.env`)

`backend/.env` est créé à partir de `backend/.env.example` et n'est jamais
commité. Principales variables :

```env
# Réseau : local uniquement par défaut
API_HOST=127.0.0.1
API_PORT=8000

# Authentification locale entre l'extension et le backend
AGENT_AUTH_ENABLED=true
# vide : un jeton est généré automatiquement
AGENT_AUTH_TOKEN=
# vide : emplacement par défaut dans le profil utilisateur
AGENT_TOKEN_PATH=

# Moteurs d'analyse
CODE_ANALYSIS_ENABLED=true
SECRET_DETECTION_ENABLED=true
DEPENDENCY_INVENTORY_ENABLED=true
DEPENDENCY_VULNERABILITY_ENABLED=true   # appels sortants vers l'API OSV

# Assistance IA optionnelle (désactivée sans clé)
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4o-mini
CODE_AI_ENRICHMENT_ENABLED=false

# Stockage
DATABASE_PATH=data/alerts.db
```

Les autres sections de `.env.example` ne sont pas nécessaires à
l'extension et peuvent conserver leurs valeurs par défaut.

### Paramètres de l'extension

Les paramètres sont accessibles dans **Settings → Extensions**. Il est
possible de rechercher les clés ci-dessous :

| Paramètre                    | Valeur par défaut       | Rôle                                               |
| ---------------------------- | ----------------------- | -------------------------------------------------- |
| `backendUrl`                 | `http://127.0.0.1:8000` | Adresse du backend (portée machine, non modifiable par un repository) |
| `allowRemoteBackend`         | `false`                 | Autorise un backend situé sur une autre machine    |
| `autoScan` / `scanOnSave`    | `true`                  | Analyse automatique et analyse à la sauvegarde     |
| `monitoring.enabled`         | `true`                  | Surveillance continue des fichiers modifiés        |
| `monitoring.debounceMs`      | `1200`                  | Délai avant l'analyse d'un fichier modifié         |
| `project.secretDetection`    | `true`                  | Détection locale des secrets                       |
| `project.dependencyAnalysis` | `true`                  | Inventaire des dépendances                         |
| `project.vulnerabilityCheck` | `true`                  | Recherche de vulnérabilités (via le backend)       |
| `project.apiSecurity`        | `true`                  | Analyse statique des routes d'API                  |
| `git.enabled`                | `true`                  | Analyse des changements Git                        |
| `git.prePushProtection`      | `warn`                  | `off`, `warn` ou `block` pour la vérification avant push |
| `ai.assistant`               | `true`                  | Assistant IA (nécessite une clé côté backend)      |
| `ci.policy`                  | `warn`                  | Politique affichée dans la posture de sécurité     |

## Utilisation

1. **Démarrer le backend** (voir [Installation](#5-démarrer-le-backend)).
2. **Ouvrir un projet** dans VS Code avec CyberGuard activé. L'extension
   s'active au démarrage et découvre le contexte du projet : langages,
   frameworks et fichiers sensibles. Lorsque la détection des secrets ou
   l'analyse des dépendances est activée, elle recherche également les
   secrets et les dépendances. Le panneau *Project* de la vue Security
   affiche le résultat.
3. **Travailler normalement.** L'enregistrement d'un fichier déclenche son
   analyse. Les fichiers modifiés sur disque par d'autres outils (Git,
   gestionnaires de paquets, générateurs) sont pris en charge par la
   surveillance.
4. **Consulter les findings.** Ils sont soulignés dans l'éditeur, listés
   dans le panneau Problems et regroupés par gravité dans le panneau
   *Findings*. La barre d'état indique l'état général.
5. **Ouvrir un finding** pour afficher son panneau de détail :
   explication, impact, références CWE/OWASP et recommandations.
6. **Agir.** Appliquer une correction proposée, écarter un faux positif en
   précisant éventuellement une raison ou, si l'IA est configurée,
   demander une explication ou une proposition de correction.
7. **Avant un push**, lancer *Check Changes Before Push* pour identifier
   les problèmes introduits par le changement en cours.

Toutes les commandes sont accessibles depuis la palette de commandes
(`Ctrl+Shift+P`) : *Scan Current File*, *Scan Workspace*, *Scan Project
Security*, *Refresh Project Security*, *Scan Git Changes*, *Check Changes
Before Push*, *Refresh Findings*, *Clear Findings*, *Check Backend* ainsi
que les commandes IA.

## Workflow de sécurité

```text
Développeur
   ↓
Modification du code / du projet   (édition, sauvegarde, git pull, changement de branche, générateur)
   ↓
Surveillance CyberGuard            (file watcher, empreinte, file d'analyse)
   ↓
Analyse de sécurité                (règles de code, secrets, dépendances, routes d'API)
   ↓
Findings                           (stockés par le backend, source de vérité unique)
   ↓
Risque / Contexte                  (gravité, confiance, CWE/OWASP, attribution Git)
   ↓
Retour au développeur              (diagnostics, vue Security, notifications)
   ↓
Remédiation / Assistance IA optionnelles
```

**Modifications effectuées en dehors de l'éditeur.** La surveillance est
pilotée par le système de fichiers, et non par la sauvegarde. Après un
`git pull` :

```text
git pull → fichier modifié sur disque → FileSystemWatcher → changement détecté
         → analyse automatique → findings mis à jour
```

Ce scénario a été validé dans une véritable instance de VS Code, avec le
backend réel et un fichier ouvert dans l'éditeur. Les nouveaux findings
sont apparus en quelques secondes, sans `Ctrl+S`, sans scan manuel et sans
redémarrage de VS Code. Le fichier a été analysé une seule fois et aucune
analyse supplémentaire n'a suivi.

## Tests

**Extension** (depuis `vscode-extension/`) :

```powershell
npm run typecheck    # vérification TypeScript stricte
npm test             # compile et exécute les tests unitaires (lanceur de tests Node.js)
```

**Backend** (depuis `backend/`, environnement virtuel activé) :

```powershell
python -m pytest -q
```

Les tests ne nécessitent ni accès réseau, ni backend en fonctionnement, ni
clé d'API. Les services externes (client HTTP, base de vulnérabilités,
fournisseur d'IA) sont simulés. Un test de contrat de chaque côté vérifie
que l'extension et le backend respectent `contract/api-contract.json`.

## Compilation et packaging

Depuis `vscode-extension/` :

```powershell
npm run compile            # build de développement → dist/extension.js, dist/ci-check.js
npm run build              # typecheck + build de production minifié
npx @vscode/vsce package   # crée un .vsix (lance d'abord le build de production)
```

Le projet ne contient pas de fichier `LICENSE` (`"license": "UNLICENSED"`) :
`vsce` demande donc une confirmation. La commande `npx @vscode/vsce package
--skip-license` permet d'éviter cette question. Le fichier `.vsix` obtenu
s'installe via **Extensions → … → Install from VSIX…**.

Le CI Check s'exécute avec un backend en fonctionnement :

```powershell
node dist/ci-check.js --root .. --policy warn   # --help liste toutes les options
```

`dist/` est un produit de compilation et n'est pas versionné.

## Sécurité et confidentialité

- **Les secrets ne sont jamais commités.** `backend/.env` est exclu par le
  `.gitignore`, de même que les bases de données, les clés privées, les
  certificats, les fichiers d'identifiants et le jeton d'authentification
  local.
- **`backend/.env.example` n'est qu'un modèle.** Toutes ses valeurs
  sensibles sont vides.
- **La valeur des secrets ne quitte jamais le poste.** La détection est
  locale, et seule une preuve masquée parvient au backend, qui la masque à
  nouveau avant de la stocker.
- **Les requêtes IA sont réduites au minimum et masquées.** Un finding est
  transmis par son identifiant, et une question posée dans le chat est
  masquée avant de quitter l'éditeur. Le modèle reçoit du backend un
  contexte réduit : preuve masquée, chemins relatifs et métadonnées du
  projet. Il ne reçoit jamais le contenu des fichiers, ni clé, ni mot de
  passe.
- **Les fichiers sensibles ne sont pas lus.** Les fichiers `.env`, les clés
  privées, les certificats et les fichiers d'identifiants sont signalés
  uniquement par leur chemin.
- **Le contenu des fichiers n'est envoyé qu'au backend configuré.** Il est
  transmis fichier par fichier pour analyse, jamais journalisé, et limité
  à 400 KB par fichier.
- **API protégée.** Toutes les routes du backend utilisées par l'extension
  exigent le jeton local, à l'exception du health check.

## Limites

- L'analyse du code repose sur des règles à base de motifs. Elle couvre
  cinq langages et peut produire des faux positifs ou manquer des
  problèmes qui nécessiteraient une analyse de flux de données.
- L'analyse des API est statique. Les routes enregistrées dynamiquement,
  ou celles des frameworks absents de la liste prise en charge, ne sont pas
  signalées.
- La vérification avant push se lance depuis l'éditeur. Aucun hook Git
  n'est installé : un `push` effectué depuis un terminal n'est donc pas
  vérifié.
- La surveillance couvre le premier dossier du workspace. L'analyse
  incrémentale au niveau du projet démarre après la découverte initiale du
  projet.
- La vérification des vulnérabilités nécessite un accès réseau du backend
  vers OSV. Les versions non figées ne peuvent pas être vérifiées.
- L'interface utilisateur est actuellement en français.

## Perspectives d'évolution

Il s'agit de pistes possibles, et non de fonctionnalités déjà disponibles :

- Meilleure corrélation entre les findings des différents moteurs.
- Analyse plus approfondie, par exemple un suivi des flux de données pour
  les règles d'injection.
- Nouvelles règles de sécurité et nouveaux langages.
- Contexte plus riche pour l'assistant IA et propositions de correction
  mieux ciblées.
- Amélioration des performances sur les très grands repositories.
- Intégration CI/CD plus poussée, par exemple des modèles de pipeline prêts
  à l'emploi.

## Licence

Ce repository est privé et n'est pas distribué sous une licence open
source. Le manifeste de l'extension déclare `"license": "UNLICENSED"`. Tous
droits réservés.

## À propos du projet

CyberGuard VS Code a été développé dans le cadre d'un projet de
cybersécurité visant à intégrer l'analyse de sécurité au processus de
développement logiciel, au plus près du moment où le code est écrit.
