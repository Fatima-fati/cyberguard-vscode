# Wazuh Security — extension VS Code + backend FastAPI

Analyse de sécurité du code **pendant** le développement, directement dans
VS Code. À chaque sauvegarde — et à chaque modification d'un fichier
directement sur disque (`git pull`, changement de branche, outil externe) —
le fichier est envoyé à un backend FastAPI local qui applique un moteur de
règles déterministe et renvoie les problèmes détectés : gravité,
explication, conséquences possibles, recommandation et, éventuellement, un
correctif.

Ce dépôt contient les **deux moitiés indispensables** du produit :

| Dossier             | Rôle                                                    |
| ------------------- | ------------------------------------------------------- |
| `vscode-extension/` | L'extension VS Code (TypeScript). Interface uniquement.  |
| `backend/`          | L'API FastAPI (Python). Toute l'analyse de sécurité.     |

> **L'extension seule ne réalise aucune analyse.** Elle ne contient aucune
> règle, aucune clé et aucune logique de détection : elle envoie un
> document au backend et affiche la réponse. **Le backend FastAPI est donc
> indispensable** — sans lui, l'extension se charge, signale que le backend
> est injoignable, et ne détecte rien.

## 1. Présentation

L'extension ajoute à VS Code :

- une analyse automatique **à la sauvegarde** des fichiers Python,
  JavaScript, TypeScript (JSX/TSX compris), PHP et Java ;
- une **surveillance continue** du dossier ouvert : un fichier modifié sur
  disque, même sans passer par l'éditeur, est réanalysé seul (§7) ;
- des **diagnostics** natifs (soulignement, panneau Problèmes, survol
  détaillé avec CWE et OWASP) ;
- une vue **Security** dans la barre d'activité (Project + Risk Overview +
  Findings) ;
- la **sécurité du projet** : secrets écrits en dur, inventaire des
  dépendances, vulnérabilités connues (OSV), sécurité des API déclarées
  (§12) ;
- l'analyse des **changements Git** et une vérification **avant push**
  lancée depuis l'éditeur (§7) ;
- des **Quick Fix** appliqués uniquement après confirmation explicite ;
- une fiche détaillée par signalement ;
- un **assistant IA facultatif**, côté backend : enrichissement,
  explication, résumé, correctif proposé dans un diff et jamais appliqué
  sans confirmation ;
- un **contrôle CI/CD** en ligne de commande (`node dist/ci-check.js`).

Le backend, lui, détient les règles, la persistance SQLite, les
informations d'identification et — si elle est activée — la seule
connexion à OpenAI.

## 2. Architecture

```
┌────────────────────┐   HTTP /api/code/*   ┌──────────────────────┐
│  VS Code Extension │ ───────────────────► │   Backend FastAPI    │
│  (TypeScript)      │ ◄─────────────────── │   (Python 3.12)      │
│                    │      findings        │                      │
│  diagnostics       │                      │  moteur de règles    │
│  vue Security      │   SSE /api/stream    │  enrichissement IA   │
│  quick fix         │ ◄─────────────────── │  SQLite (findings)   │
│  détection secrets │                      │                      │
│  inventaire deps   │  HTTP /api/project/* │  base OSV (réseau)   │
└────────────────────┘ ───────────────────► └──────────────────────┘
```

La détection de secrets et l'inventaire des dépendances tournent **dans
l'extension** : lire un fichier du poste pour y chercher un secret est une
opération locale, et l'envoyer à un serveur pour la même raison n'en serait
pas une. Seule une preuve *expurgée* traverse. L'interrogation de la base
de vulnérabilités est faite par le backend, seul détenteur de la sortie
réseau. Voir §12.

Ce que l'extension ne fait **jamais** :

```
VS Code → Wazuh Manager API   ✗
VS Code → Wazuh Indexer       ✗
VS Code → OpenAI              ✗
```

Le backend expose par ailleurs des routes de supervision Wazuh
(`/api/alerts`, `/api/servers`, `/api/monitoring/*`, `/api/ai/*`) héritées
du projet de supervision. **Elles ne sont pas nécessaires à l'extension** :
ni l'analyse de code, ni la détection de secrets, ni l'inventaire des
dépendances, ni l'analyse de vulnérabilités ne dépendent d'un Wazuh en
fonctionnement ou de l'Indexer. Ces fonctions répondent à l'identique avec
Wazuh complètement arrêté, et deux suites de tests le vérifient. Seules les
routes `/api/code/*`, `/api/project/*`, `/api/security/*` et `/api/stream`
sont utilisées par l'extension.

### Endpoints utilisés par l'extension

Toutes exigent le jeton local, **sauf** `GET /api/code/health` : c'est la
route de diagnostic, et l'exiger rendrait un problème d'authentification
indiscernable d'un backend éteint. Voir [docs/SECURITY.md](docs/SECURITY.md).

| Méthode | Chemin                                | Auth | Rôle                                        |
| ------- | ------------------------------------- | ---- | ------------------------------------------- |
| GET     | `/api/code/health`                    | —    | Version, règles, état IA, `auth_required`   |
| POST    | `/api/code/scan`                      | ✓    | Analyse un document (contenu + empreinte)   |
| GET     | `/api/code/scans/{scan_uid}`          | ✓    | Relit une analyse (état terminal, enrichie) |
| GET     | `/api/code/findings`                  | ✓    | Findings ouverts, filtrables par projet     |
| POST    | `/api/code/findings/{uid}/fix`        | ✓    | Demande un correctif (ne l'applique pas)    |
| POST    | `/api/code/findings/{uid}/decision`   | ✓    | Marque « corrigé » ou « ignoré »            |
| POST    | `/api/project/discover`               | ✓    | Enregistre un projet, retourne son identifiant |
| POST    | `/api/project/{uid}/index`            | ✓    | Soumet l'index, reçoit le contexte          |
| GET     | `/api/project/{uid}/context`          | ✓    | Relit le contexte enregistré                |
| GET     | `/api/security/health`                | ✓    | Capacités du moteur de sécurité projet      |
| POST    | `/api/project/{uid}/secrets`          | ✓    | Balayage de secrets (preuves **expurgées**) |
| POST    | `/api/project/{uid}/dependencies`     | ✓    | Inventaire + analyse de vulnérabilités      |
| GET     | `/api/project/{uid}/findings`         | ✓    | Findings de sécurité, toutes familles       |
| GET     | `/api/stream`                         | ✓    | Flux SSE, cloisonné par `?project_uid=`     |

Routes complémentaires du même préfixe : `GET /api/code/rules` et
`GET /api/code/stats`.

## 3. Installation

### 3.1 Node.js

Nécessaire uniquement pour compiler et tester l'extension.

- **Node.js 18 ou plus récent** et npm : <https://nodejs.org>
- Vérification :

  ```powershell
  node --version
  npm --version
  ```

- **VS Code 1.85** ou plus récent est également requis.

### 3.2 Python

Nécessaire pour le backend.

- **Python 3.12** (ou 3.11+) : <https://www.python.org/downloads/>
- Vérification :

  ```powershell
  python --version
  ```

### 3.3 Dépendances

```powershell
# Backend
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt   # pytest, pour les tests

# Extension
cd ..\vscode-extension
npm ci
```

Puis créer la configuration locale du backend :

```powershell
cd ..\backend
copy .env.example .env
```

`backend/.env.example` ne contient **aucun secret** : toutes les valeurs
sensibles y sont vides. Pour la seule analyse de code, le fichier par
défaut suffit — aucune clé n'est nécessaire.

## 4. Démarrage du backend

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Vérifications :

- <http://127.0.0.1:8000/api/code/health> → `{"status":"ok", ...}`
- <http://127.0.0.1:8000/docs> → documentation OpenAPI

`--host 127.0.0.1` est le mode **développement local** : le backend n'est
joignable que depuis cette machine. Le démarrage annonce le mode retenu
dans les journaux. Pour un déploiement joignable depuis le réseau, voir
[docs/SECURITY.md](docs/SECURITY.md) § 3.

Au premier démarrage, le backend :

1. **recrée la base SQLite** `backend/data/alerts.db` (`store.init_db()`) —
   elle n'est pas versionnée ;
2. **génère son jeton d'authentification** dans
   `~/.wazuh-security/agent-token`, hors du dépôt. L'extension le lit
   automatiquement et le conserve dans le trousseau du système : il n'y a
   rien à configurer, et rien à copier nulle part.

Sans backend démarré, l'extension reste chargée, signale que le backend est
injoignable et n'invente aucun résultat.

## 5. Lancer l'extension (F5)

1. Ouvrir le dossier **`vscode-extension/`** dans VS Code (pas la racine).
2. `npm ci` puis `npm run compile`.
3. Appuyer sur **F5** (« Run Extension ») : une seconde fenêtre VS Code
   s'ouvre, extension chargée.
4. Dans cette fenêtre, ouvrir un projet et sauvegarder un fichier Python,
   JavaScript, TypeScript, PHP ou Java.

Le backend doit tourner en parallèle. Le canal **Affichage → Sortie →
Wazuh Security** trace chaque analyse ; le contenu des fichiers n'y
apparaît jamais.

### Compiler et packager

```powershell
cd vscode-extension
npm run typecheck    # vérification TypeScript stricte, sans build
npm run compile      # build de développement → dist/extension.js, dist/ci-check.js
npm run build        # typecheck + build de production (minifié)
npx @vscode/vsce package   # produit un .vsix (lance `npm run build` via vscode:prepublish)
```

`dist/` n'est pas versionné : il est régénéré par ces commandes, par la
tâche F5 et au packaging. Le projet n'ayant pas de fichier `LICENSE`
(`"license": "UNLICENSED"`), `vsce` le signale et demande confirmation ;
`--skip-license` permet de packager malgré tout. Le `.vsix` s'installe par **Extensions → … →
Install from VSIX…**.

## 6. Configuration de l'extension

| Réglage                       | Défaut                  | Rôle                                      |
| ----------------------------- | ----------------------- | ----------------------------------------- |
| `wazuhSecurity.backendUrl`    | `http://127.0.0.1:8000` | Adresse du backend d'analyse. **Portée `machine`** : non modifiable par un dépôt |
| `wazuhSecurity.allowRemoteBackend` | `false` | Autorise un backend hors de cette machine. **Portée `machine`** |
| `wazuhSecurity.project.discoverOnStartup` | `true` | Établit le contexte du projet à l'ouverture du dossier |
| `wazuhSecurity.autoScan`      | `true`                  | Active l'analyse automatique              |
| `wazuhSecurity.scanOnSave`    | `true`                  | Analyse à chaque sauvegarde               |
| `wazuhSecurity.syncOnStartup` | `true`                  | Reprend les findings ouverts au démarrage |
| `wazuhSecurity.aiEnrichment`  | `false`                 | Demande au **backend** un enrichissement IA |
| `wazuhSecurity.monitoring.enabled` | `true`             | Surveille les fichiers du projet et réanalyse ceux qui changent |
| `wazuhSecurity.monitoring.debounceMs` | `1200`          | Anti-rebond avant l'analyse d'un fichier modifié (200–10 000 ms) |
| `wazuhSecurity.git.enabled`   | `true`                  | Analyse des changements Git (API Git de VS Code, aucune commande `git`) |
| `wazuhSecurity.git.prePushProtection` | `warn`          | `off` / `warn` / `block` pour « Check Changes Before Push » |
| `wazuhSecurity.project.apiSecurity` | `true`            | Analyse statique des routes d'API déclarées |
| `wazuhSecurity.ai.assistant`  | `true`                  | Assistant IA (sans effet si le backend n'a pas de clé) |
| `wazuhSecurity.ci.policy`     | `warn`                  | Politique affichée dans la posture de sécurité |

La liste complète, avec la description de chaque réglage, figure dans
**Paramètres → Extensions → Wazuh Security**.

`backendUrl` vaut `http://127.0.0.1:8000` par défaut : c'est l'adresse sur
laquelle uvicorn écoute avec la commande ci-dessus. Si le backend tourne sur
un autre port de cette machine, modifier ce réglage dans les paramètres VS
Code.

**Un backend sur une autre machine exige deux gestes délibérés** :
renseigner `backendUrl` *et* activer `wazuhSecurity.allowRemoteBackend`.
La raison est que cette adresse décide où part le contenu intégral de
chaque fichier analysé : les deux réglages sont de portée `machine` — donc
hors de portée du `.vscode/settings.json` d'un dépôt cloné — et une adresse
distante autorisée reste signalée en permanence dans la barre d'état. Les
adresses refusées (protocole inattendu, identifiants dans l'URL, chemin de
base) donnent un message explicite et un repli annoncé sur la boucle
locale. Détail dans [docs/SECURITY.md](docs/SECURITY.md) § 4.

## 7. Utilisation

### Analyse à la sauvegarde

Sauvegarder un fichier pris en charge déclenche l'analyse. Un
**anti-rebond de 800 ms** regroupe les sauvegardes rapprochées, l'empreinte
SHA-256 du contenu accompagne la requête, et VS Code n'est jamais bloqué :
la requête est asynchrone. Une sauvegarde pendant une analyse annule et
remplace celle en cours — un résultat qui ne correspond plus au contenu
affiché n'est jamais montré.

Ne partent **jamais** au backend : `.env` et ses variantes, clés privées et
certificats (`*.pem`, `*.key`, `*.p12`, `id_rsa`…), `.npmrc`, `.pypirc`,
`credentials`, ainsi que `node_modules/`, `dist/`, `build/`, `.git/`,
`.venv/`, `__pycache__/`, les fichiers listés dans le `.gitignore` du
projet, les documents non enregistrés, les fichiers vides et ceux
dépassant 400 Ko.

### Surveillance automatique des fichiers

Avec `wazuhSecurity.monitoring.enabled` (actif par défaut), l'extension
surveille le premier dossier du workspace et réanalyse **uniquement les
fichiers qui changent**, sans parcours complet du projet :

```
FileSystemWatcher (**/*)      création / modification / suppression
  → classification            dossier exclu (.git, node_modules…) ? binaire ?
                              sensible (.env, clés) : journalisé, jamais lu
  → empreinte                 taille, date, SHA-256 : un fichier réécrit à
                              l'identique ne déclenche rien
  → file d'attente            anti-rebond, dédoublonnage, priorité au fichier
                              que l'on vient d'enregistrer, concurrence bornée
  → moteurs existants         /api/code/scan, secrets, API, dépendances
  → findings                  relus chez le backend, vue et Problems à jour
```

Code : `vscode-extension/src/monitor/` (`projectMonitor.ts`,
`changeClassification.ts`, `fileSignature.ts`, `scanQueue.ts`,
`securityBaseline.ts`).

La partie *sécurité projet* (secrets, API, dépendances) attend qu'une
première découverte du projet ait abouti dans la session : sans cet état de
référence, un lot incomplet effacerait les constats des autres fichiers. Le
journal l'annonce. L'analyse de code, elle, n'en dépend pas.

#### Modifications faites hors de l'éditeur, par exemple `git pull`

Le déclencheur est le **système de fichiers**, pas la sauvegarde : un
fichier modifié directement sur disque est détecté comme un autre.

```
git pull
  → le fichier est modifié sur disque
  → FileSystemWatcher le signale
  → détection du changement (classification + empreinte)
  → scan automatique du fichier
  → mise à jour des findings (vue Security, panneau Problems)
```

Ce scénario a été **validé dans une vraie instance VS Code**, extension
active et backend réel : fichier ouvert dans l'éditeur, `git pull
--ff-only` exécuté hors de VS Code et apportant une commande système
construite dynamiquement et une clé d'accès écrite en dur. Les findings
correspondants sont apparus en quelques secondes **sans `Ctrl+S`, sans scan
manuel et sans redémarrage**. Plusieurs événements pour le même fichier ont
produit une seule analyse de code et une seule soumission de secrets, et
aucune nouvelle analyse n'a suivi (pas de boucle). Cette validation a été
faite manuellement : elle ne fait pas partie des suites automatisées du §8.

Non couvert par cette validation : un fichier portant des modifications
**non enregistrées** dans l'éditeur au moment du `git pull` (VS Code
signale alors lui-même le conflit).

### Changements Git et vérification avant push

**Wazuh Security: Scan Git Changes** analyse les fichiers modifiés et
distingue ce que **le changement introduit** de ce qui existait déjà.
Tout passe par l'API de l'extension Git de VS Code : aucune commande `git`
n'est exécutée. Au-delà de `wazuhSecurity.git.maxChangedFiles`, l'analyse
passe en mode réduit et l'annonce.

**Wazuh Security: Check Changes Before Push** applique
`wazuhSecurity.git.prePushProtection`. Seuls les problèmes `CRITICAL` ou
`HIGH` **introduits** par le changement comptent. **Aucun hook Git n'est
installé** : un `push` lancé depuis un terminal n'est pas intercepté, et en
mode `block`, « Pousser quand même » reste toujours proposé.

### Contrôle CI/CD

Le même moteur tourne hors de VS Code, backend joignable requis :

```powershell
cd vscode-extension
npm run compile
node dist/ci-check.js --root .. --policy warn   # --help pour toutes les options
```

Rapport JSON sur la sortie standard, journal sur la sortie d'erreur. Aucune
IA, aucun score : les conditions (`CRITICAL`, `HIGH`, secrets, dépendances
vulnérables) sont des faits établis par les moteurs de détection.

### Scan Current File

**Wazuh Security: Scan Current File** analyse le fichier actif à la
demande, même si `scanOnSave` est désactivé. Si le fichier n'est pas
analysable, la commande explique pourquoi.

### Scan Workspace

**Wazuh Security: Scan Workspace** analyse tous les fichiers pris en
charge du workspace (300 au maximum), avec une barre de progression
annulable.

Autres commandes : **Clear Findings**, **Refresh Findings**, **Analyze
with AI** (visible seulement si le backend annonce l'IA active) et
**Check Backend** (diagnostic de connexion).

### Diagnostics

Chaque finding devient un diagnostic VS Code natif :

| Sévérité backend | Diagnostic VS Code |
| ---------------- | ------------------ |
| `CRITICAL`       | Error              |
| `HIGH`           | Error              |
| `MEDIUM`         | Warning            |
| `LOW`            | Information        |

Le survol affiche le titre, la gravité, les références CWE et OWASP,
l'explication, les conséquences possibles et la recommandation. La barre
d'état résume : `Sécurité : 1 critique, 2 élevées`, ou `Sécurité : OK`.

### Quick Fix

L'ampoule (`Ctrl+.`) propose selon le cas :

| Action             | Effet                                                                 |
| ------------------ | --------------------------------------------------------------------- |
| **Corriger**       | `POST /api/code/findings/{uid}/fix`, affichage de la ligne avant/après, écriture **après confirmation explicite** uniquement. |
| **Voir le détail** | Ouvre la fiche complète (explication, conséquences, facteurs de risque). |
| **Ignorer**        | `POST /api/code/findings/{uid}/decision` : faux positif, avec raison facultative. |

La correction est appliquée par un `WorkspaceEdit` : **annulable par
Ctrl+Z** et visible dans le diff Git. Le backend n'écrit jamais dans vos
fichiers — il décrit la modification, l'éditeur l'applique. Un correctif
est refusé si la ligne a changé depuis l'analyse.

### Findings

La vue **Security** (icône bouclier) affiche deux arbres natifs :
*Risk Overview* (compteurs par sévérité) et *Findings* (regroupés par
gravité). Un clic ouvre le fichier, place le curseur sur la zone concernée
et affiche la fiche détaillée.

Aucun finding n'est supprimé : « corrigé » et « ignoré » sont des états,
consultables ensuite via `GET /api/code/findings`. Au démarrage,
`syncOnStartup` reprend les findings encore ouverts sans rien réanalyser ;
les diagnostics ne sont soulignés que si l'empreinte du fichier correspond
toujours.

### SSE et enrichissement IA

L'enrichissement IA est **désactivé par défaut des deux côtés**. Il exige :

- côté backend : `CODE_AI_ENRICHMENT_ENABLED=true` **et** une
  `OPENAI_API_KEY` valide dans `backend/.env` ;
- côté extension : `wazuhSecurity.aiEnrichment` à `true`.

Tant que l'une des deux manque, **aucune requête ne part vers OpenAI** :
seules les règles déterministes s'appliquent.

```
sauvegarde → règles (immédiat)           → diagnostics affichés
           → enrichissement IA (backend) → « Sécurité : analyse IA… »
           → event SSE code_finding      → diagnostic mis à jour
           → event SSE code_scan         → barre d'état finalisée
```

L'extension ouvre **une seule connexion** SSE sur `/api/stream` à
l'activation et n'écoute que `code_finding`. Le flux n'est **jamais
indispensable** : le résultat du scan arrive par la réponse HTTP, et
l'état terminal est relu par `GET /api/code/scans/{scan_uid}`. En cas de
coupure, la reconnexion est progressive (1 s, 2 s, 4 s, 8 s, 16 s, puis
30 s au maximum) et silencieuse. Ce qui transite n'est jamais journalisé.

## 8. Tests

### Tests de l'extension

```powershell
cd vscode-extension
npm ci
npm run build        # typecheck strict + build de production
npm test             # suites de vscode-extension/test/*.test.ts
```

Lanceur natif de Node, aucune dépendance ajoutée. `fetch`, le minuteur, le
système de fichiers et la réserve de secrets sont tous injectés : aucun
réseau, aucun backend, aucune clé requise, et aucune lecture du profil de
l'utilisateur.

Les suites couvrent l'analyse, le client HTTP, le store de findings, le
garde-fou de correction, le registre de notifications, le client SSE, le
HTML de la fiche, la présentation, et depuis les phases 0 et 1 : la
validation de l'adresse du backend, la résolution du jeton, l'identité de
projet, la découverte locale, le service de contexte et le contrat d'API ;
puis la surveillance (classification, file d'attente, monitoring), les
changements Git, la sécurité d'API, l'assistant IA, la remédiation et la
posture CI/CD.

Les parties liées à l'API VS Code (diagnostics, ampoule, webview, barre
d'état) sont couvertes par le typecheck strict et se vérifient au
lancement F5.

### Tests du backend

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
python -m pytest -q
```

Les dépendances externes sont toutes simulées
(`httpx.MockTransport`, base SQLite temporaire, client Wazuh bouchonné,
fournisseur de vulnérabilités doublé) : **aucun appel réseau réel, aucun
Wazuh en fonctionnement requis, aucune clé OpenAI nécessaire, aucune
interrogation d'osv.dev**.

`tests/test_security_without_wazuh.py` va plus loin que la simulation : il
vérifie sur le **code source** que `app/security` ne nomme Wazuh nulle
part, puis remplace toute la couche Wazuh par des objets qui lèvent à la
moindre sollicitation et rejoue les routes de la phase 2.

La suite tourne **authentification activée**, avec un jeton de test
installé par `conftest.py` : elle exerce donc le chemin réellement servi en
production, et non une variante sans contrôle.

### Test de contrat

`contract/api-contract.json` décrit le contrat partagé, et **deux** tests
le vérifient — un de chaque côté :

```
backend/tests/test_api_contract.py         → schéma OpenAPI de FastAPI
vscode-extension/test/apiContract.test.ts  → types TypeScript
```

Une divergence d'un côté ou de l'autre fait échouer un build. Le fichier
liste aussi des **champs interdits** (contenu de fichier, chemin absolu,
URL de remote Git, score de sécurité) : leur apparition dans un modèle fait
échouer la suite.

## 9. Structure du projet

```
VsCode-extension/
├── .gitignore
├── README.md                  ← ce fichier
├── contract/
│   └── api-contract.json      contrat partagé extension ↔ backend,
│                              vérifié des deux côtés par un test
├── docs/
│   ├── SECURITY.md            modèle de sécurité de l'agent
│   └── PROJECT_CONTEXT.md     contexte de projet en détail
├── vscode-extension/          extension VS Code (TypeScript)
│   ├── .vscode/               launch.json (F5) + tasks.json
│   ├── resources/             shield.svg (icône de la vue Security)
│   ├── src/
│   │   ├── analysis/          filtrage, empreinte, contrôleur de scan
│   │   ├── api/               backendClient, streamClient, backendUrl,
│   │   │                      agentToken
│   │   ├── monitor/           surveillance continue : watcher,
│   │   │                      classification, empreintes, file d'attente
│   │   ├── git/               changements Git, attribution, avant push
│   │   ├── apisec/            analyse statique des routes d'API
│   │   ├── project/           découverte, identité, contexte, types
│   │   ├── security/          motifs de secrets, scanner, expurgation,
│   │   │                      faux positifs, inventaire de dépendances,
│   │   │                      adaptateur de findings
│   │   ├── ai/, remediation/  assistant IA, correctif assisté
│   │   ├── posture/           posture de sécurité, politique CI/CD
│   │   ├── cli/               contrôle CI/CD (dist/ci-check.js)
│   │   ├── diagnostics/       provider, survol, mapping de sévérité,
│   │   │                      diagnostics de sécurité projet
│   │   ├── state/             findingsStore, notificationLedger
│   │   ├── ui/                vues Project et Security, quick fix, fiche,
│   │   │                      barre d'état
│   │   ├── i18n/              libellés
│   │   └── extension.ts       activation / désactivation
│   ├── test/                  tests unitaires (lanceur natif de Node)
│   ├── .vscodeignore
│   ├── esbuild.mjs
│   ├── package.json
│   ├── package-lock.json
│   ├── tsconfig.json
│   └── README.md              documentation détaillée de l'extension
└── backend/                   API FastAPI (Python)
    ├── app/
    │   ├── code/              analyse de code : rules, scanner, routes…
    │   ├── project/           contexte de projet : discovery, context,
    │   │                      routes, schemas, ai_contract
    │   ├── security/          findings unifiés, expurgation, secrets,
    │   │                      dépendances, providers/ (OSV)
    │   ├── ai/                enrichissement IA, sanitizer, risque
    │   ├── notifier/          SSE (stream.py), e-mail, Discord
    │   ├── auth.py            jeton local, dépendance d'authentification
    │   ├── config.py          réglages (pydantic-settings, lit .env)
    │   ├── paths.py           validation des chemins relatifs, partagée
    │   ├── main.py            application FastAPI
    │   ├── routes.py          routes /api/*
    │   └── store.py           SQLite (init_db, persistance)
    ├── tests/                 suite pytest
    ├── data/
    │   └── .gitkeep           la base est recréée au démarrage
    ├── .env                   configuration locale — jamais versionnée
    ├── .env.example           modèle sans secret
    ├── pytest.ini
    ├── requirements.txt
    └── requirements-dev.txt
```

## 10. Sécurité et gestion des `.env`

> Le modèle de sécurité complet — authentification, cloisonnement du flux,
> validation de l'adresse du backend, ce que le contexte de projet collecte
> et refuse de collecter — est décrit dans
> **[docs/SECURITY.md](docs/SECURITY.md)**. Cette section en résume la
> partie « fichiers de configuration ».

- **`backend/.env` est local et ne doit jamais être versionné ni partagé.**
  Il est couvert par le `.gitignore` racine.
- **`backend/.env.example` est le seul fichier de configuration
  partageable.** Toutes ses valeurs sensibles (`WAZUH_API_PASSWORD`,
  `INDEXER_PASSWORD`, `OPENAI_API_KEY`, `SMTP_PASSWORD`,
  `DISCORD_WEBHOOK_URL`) sont **vides**. Ne jamais y écrire une valeur
  réelle.
- **`backend/data/*.db` n'est pas versionnée** : elle peut contenir des
  alertes réelles. Elle est recréée automatiquement par `store.init_db()`.
- **L'extension ne contient aucun secret** : ni clé, ni mot de passe, ni
  jeton. La clé OpenAI, si elle est configurée, reste exclusivement côté
  backend et n'est jamais renvoyée au client ni journalisée.
- **Le contenu des fichiers analysés** n'est envoyé qu'au backend local,
  fichier par fichier, jamais journalisé, jamais conservé après la
  requête. Le workspace transmis est son **nom**, pas le chemin absolu.
- Si une clé a été exposée par le passé (fichier partagé, capture,
  historique Git), **elle doit être considérée comme compromise** : la
  révoquer chez le fournisseur et en générer une nouvelle. La retirer du
  fichier ne suffit pas.

Avant tout premier `git init` / `git push`, vérifier qu'aucun secret réel
ne se trouve dans les fichiers destinés au dépôt :

```bash
git ls-files | grep -Ei "\.env|\.pem|\.key|agent-token"
```

`.gitignore` ne protège que ce qui n'est **pas déjà suivi** : un fichier
ajouté à l'index avant l'ajout d'une règle y reste.

## 11. Contexte de projet

À l'ouverture d'un dossier, l'agent établit ce qu'il sait du projet :
langages, frameworks, type, fichiers importants et sensibles, présence d'un
dépôt Git. En arrière-plan, annulable, sans bloquer l'éditeur.

La découverte n'indexe que des **métadonnées** — chemin relatif, taille,
empreinte, date. Aucun contenu de fichier n'est transmis, et le contenu des
fichiers sensibles n'est **jamais lu**, pas même pour calculer une
empreinte.

Le résultat s'affiche dans la vue **Project**, à côté de Risk Overview et
Findings. La commande **« Wazuh Security: Refresh Project Security »** la
rafraîchit.

Description complète : **[docs/PROJECT_CONTEXT.md](docs/PROJECT_CONTEXT.md)**.

## 12. Sécurité du projet : secrets, dépendances, vulnérabilités

Trois moteurs **déterministes**, indépendants les uns des autres, et
indépendants de Wazuh.

> **Wazuh n'est pas requis.** Aucun de ces trois moteurs n'appelle le
> Wazuh Manager, le Wazuh Indexer ou l'API Wazuh. Ils répondent à
> l'identique avec Wazuh complètement arrêté ou absent — deux suites de
> tests le vérifient, l'une sur le code source (`app/security` ne nomme
> Wazuh nulle part), l'autre en remplaçant toute la couche Wazuh par des
> objets qui lèvent à la moindre sollicitation.

### 12.1 Où tourne quoi, et pourquoi

```
détection des secrets     EXTENSION   lire un fichier pour y chercher un
                                      secret est une opération locale ;
                                      l'envoyer à un serveur pour la même
                                      raison n'en serait pas une
inventaire dépendances    EXTENSION   les manifestes sont sur le poste
base de vulnérabilités    BACKEND     il détient la sortie réseau, et lui
                                      seul
persistance, libellés     BACKEND     une seule définition du vocabulaire
                                      affiché
```

Conséquence directe : **la valeur d'un secret ne quitte jamais la
machine.** Ce qui monte vers le backend est un chemin relatif, une ligne,
un type de secret, une confiance et une preuve déjà expurgée.

### 12.2 Détection de secrets

Lancée pendant la découverte du projet — le même parcours, sans second
passage sur le disque : la découverte lit déjà chaque fichier éligible
pour en calculer l'empreinte, et le texte est offert au moteur pendant
qu'il est en mémoire.

Reconnaît notamment : clés OpenAI et Anthropic, clés d'accès AWS, jetons
GitHub, GitLab, Slack, npm, clés Google et SendGrid, clés Stripe, webhooks
Slack et Discord, blocs de clés privées, JWT et clés de signature JWT,
en-têtes `Bearer` et `Basic`, secrets clients OAuth, mots de passe écrits
en dur, identifiants dans une URL de base de données, clés de stockage
Azure, comptes de service Google Cloud.

Un **seul** jeu de motifs couvre Python, JavaScript, TypeScript, JSON,
YAML, TOML, Java, PHP, Go, C#, Ruby et les fichiers de configuration : les
motifs d'affectation acceptent `=`, `:`, `=>` et `:=`, avec ou sans
guillemets. Une table par langage aurait divergé au premier ajout.

**Expurgation.** La valeur détectée ne quitte pas la portée de la fonction
qui l'examine : elle est pesée, puis remplacée par son masque.

```
❌ jamais stocké    sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6
✅ stocké           OpenAI API key detected: sk-proj-********
```

L'expurgation est appliquée **deux fois**, et la redondance est voulue :
côté extension pour protéger le poste (journaux, mémoire, fenêtre de
détail), côté backend pour protéger la base — celui-ci ne fait aucune
confiance à l'expurgation du client, parce qu'il écoute en local et que
tout processus de la machine peut poster sur ses routes.

**Faux positifs.** Deux traitements, jamais confondus :

| Situation                                                    | Traitement    |
| ------------------------------------------------------------ | ------------- |
| `${API_KEY}`, `<API_KEY>`, `YOUR_API_KEY`, `CHANGE_ME`       | **écarté**    |
| `process.env.X`, `os.environ[...]`, `System.getenv(...)`     | **écarté**    |
| `example.com`, valeur d'un seul caractère répété             | **écarté**    |
| fichier de test, de fixtures, d'exemple, de documentation     | **déclassé**  |
| valeur de faible entropie sur un motif d'affectation          | **déclassé**  |

La distinction porte une décision : un placeholder est écarté (l'afficher
serait toujours faux), une clé dans un fichier de test est **déclassée**
mais conservée — les secrets réels dans les fixtures existent, et c'est
précisément là qu'on oublie de les faire tourner.

**Confiance et gravité** voyagent côte à côte et ne se confondent pas. Une
détection de faible confiance ne s'affiche **jamais** en `CRITICAL` :

| Confiance | Effet sur la gravité affichée   |
| --------- | ------------------------------- |
| `HIGH`    | inchangée                       |
| `MEDIUM`  | `CRITICAL` → `HIGH`             |
| `LOW`     | plafonnée à `MEDIUM`            |

La règle protège la crédibilité du signal : une liste de critiques où un
sur deux est faux cesse d'être lue, et le jour où un vrai secret y figure,
il passe inaperçu.

**Limite assumée.** Les fichiers classés sensibles en phase 1 — `.env`,
`.pem`, `id_rsa`, `.npmrc`, `credentials` — ne sont **pas lus**, donc pas
analysés. Ils sont déjà signalés par leur chemin, et les ouvrir n'ajouterait
aucune information : leur raison d'être est de contenir des secrets. Le
moteur cherche là où un secret ne devrait pas être — code source,
configuration versionnée, workflows d'intégration continue.

### 12.3 Inventaire des dépendances

**Aucune installation, aucune exécution.** Pas de `npm install`, pas de
`pip download`, pas de `mvn dependency:tree`. Résoudre un arbre en lançant
le gestionnaire de paquets reviendrait à exécuter du code arbitraire venu
d'un dépôt qu'on est en train d'auditer — un script `postinstall` suffit.
Seuls des fichiers texte sont lus.

| Écosystème | Manifestes                                 | Fichiers de verrouillage                      |
| ---------- | ------------------------------------------ | --------------------------------------------- |
| Node.js    | `package.json`                             | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| Python     | `requirements*.txt`, `pyproject.toml`, `Pipfile` | `poetry.lock`, `Pipfile.lock`             |
| Java       | `pom.xml`, `build.gradle`, `build.gradle.kts` | —                                          |
| PHP        | `composer.json`                            | `composer.lock`                               |
| Go         | `go.mod`                                   | `go.sum`                                      |
| Ruby       | `Gemfile`                                  | `Gemfile.lock`                                |
| Rust       | `Cargo.toml`                               | `Cargo.lock`                                  |

Manifeste et lockfile ne disent pas la même chose :

```
package.json      "express": "^4.18.0"   une CONTRAINTE
package-lock.json "version": "4.18.2"    un ARTEFACT
```

Seul le second est interrogeable. Une contrainte produit une version
**vide**, qui se propage jusqu'au bout comme « non vérifiable » plutôt que
d'être devinée : inventer une version plausible à partir de `^1.2.0`
produirait une réponse — vulnérable ou saine — qui ne décrirait aucun
artefact réellement installé.

### 12.4 Analyse de vulnérabilités

Les vulnérabilités **ne sont pas écrites dans ce dépôt** : une liste de CVE
en dur serait périmée le lendemain de sa rédaction. Elles viennent d'une
base publique interrogée par le backend, derrière l'interface
`VulnerabilityProvider` (implémentation fournie : **OSV**, `osv.dev`).

Ce qui sort de la machine : **un nom de paquet, son écosystème, sa
version.** Rien d'autre — ni chemin, ni identifiant de projet, ni contenu.
C'est ce qu'un registre public connaît déjà de ces paquets. Un test
compare le corps de requête entier, pas seulement quelques champs.

Pour couper cette sortie réseau :

```bash
# backend/.env
DEPENDENCY_VULNERABILITY_ENABLED=false
```

ou, côté extension, `wazuhSecurity.project.vulnerabilityCheck: false`.
L'inventaire continue alors de fonctionner, et l'interface affiche
« vérification désactivée ».

**La règle qui gouverne tout ce moteur :**

> « Le fournisseur n'a pas répondu » **n'est pas** « il n'y a pas de
> vulnérabilité ».

Trois états, et un seul autorise à conclure :

| État                  | Ce qu'on peut en dire                          |
| --------------------- | ---------------------------------------------- |
| vérifiée et saine     | la base a répondu, rien pour ce paquet         |
| vérifiée et vulnérable | la base a répondu, voici quoi                 |
| **non vérifiée**      | version non figée, écosystème non couvert, ou base muette — **on ne sait pas** |

Une dépendance non vérifiée n'est **jamais** comptée comme saine : elle
alimente le compteur `unverified`, et le message affiché dit « impossible
de vérifier », jamais « dépendance sûre ». L'interface n'affiche même pas
de chiffre quand l'état n'est pas concluant — un « 0 » resterait lisible
comme un feu vert, même accompagné d'une infobulle que personne n'ouvre.

Modes de défaut gérés, chacun avec son état et son message : réseau coupé
(`unavailable`), délai dépassé (`timeout`), quota atteint (`rate_limited`),
erreur du service (`error`), corps illisible (`error`), vérification
désactivée (`disabled`), lot plafonné ou avis non décrit (`partial`).

### 12.5 Findings unifiés

`SecurityFinding` est le modèle commun à toutes les familles :

```
id · project_uid · category · severity · confidence · title · description
file · line_start · line_end · evidence · remediation · references
detection_engine · status · created_at
```

Catégories : `SECRET`, `DEPENDENCY`, `CODE`, `CONFIGURATION`, `API`, `GIT`.
`API` est alimentée par l'analyse statique des routes d'API. `GIT` est
**déclarée mais vide** : l'analyse Git classe les findings existants
(introduits ou préexistants) sans en créer de nouveaux. Une catégorie
annoncée et vide est honnête ; une catégorie inventée après coup casse les
filtres déjà écrits.

Les findings d'analyse de fichier (`CodeFinding`, `/api/code/*`) restent
inchangés : leur contrat est publié et l'extension s'en sert. Les deux se
rejoignent **dans la vue**, pas dans le type.

### 12.6 Interface

Secrets et dépendances vulnérables apparaissent dans la vue **Findings**
existante, triés avec le reste :

```
Security
├── Critical (2)
│   ├── Secret detected          backend/config.py:24
│   └── Vulnerable dependency    package.json
├── High (4)
├── Medium (5)
└── Low (2)
```

La vue **Project** gagne trois lignes : `Secrets`, `Dépendances` (dépliable
par écosystème) et `Vulnérabilités`. Les findings de sécurité projet
alimentent aussi le panneau **Problems**, dans une collection distincte
(`wazuhSecurity.project`) — l'utilisateur peut donc filtrer les deux
familles séparément.

Notification, telle que l'utilisateur la reçoit :

```
🚨 Secret detected

File: backend/config.py
Line: 24
Type: OpenAI API Key
Confidence: High
```

Les notifications passent par le centre de notifications existant, qui
dédoublonne et regroupe : un balayage remontant vingt secrets produit une
bulle, pas vingt.

### 12.7 Commandes et réglages

| Commande                                       | Effet                                          |
| ---------------------------------------------- | ---------------------------------------------- |
| `Wazuh Security: Scan Project Security`        | Relance découverte + secrets + dépendances     |
| `Wazuh Security: Refresh Project Security`     | Découverte, selon les réglages                 |

| Réglage                                          | Défaut | Effet                                      |
| ------------------------------------------------ | ------ | ------------------------------------------ |
| `wazuhSecurity.project.secretDetection`          | `true` | Recherche de secrets, entièrement locale   |
| `wazuhSecurity.project.dependencyAnalysis`       | `true` | Inventaire, lecture de manifestes seule    |
| `wazuhSecurity.project.vulnerabilityCheck`       | `true` | Comparaison à la base publique, via backend |

Côté backend (`backend/.env`) : `SECRET_DETECTION_ENABLED`,
`DEPENDENCY_INVENTORY_ENABLED`, `DEPENDENCY_VULNERABILITY_ENABLED`,
`VULNERABILITY_PROVIDER`, `OSV_API_URL`, `OSV_TIMEOUT_SECONDS`,
`SECRET_MAX_FINDINGS`, `PROJECT_MAX_DEPENDENCIES`.

Une capacité désactivée côté backend répond **503**, pas une liste vide :
une liste vide se lirait « rien à signaler ».

### 12.8 Autres capacités et limites

Présents, avec leurs suites de tests : analyse statique des API
(`src/apisec/`), changements Git et vérification avant push
(`src/git/`), assistant IA de sécurité — explication, résumé, chat,
correctif proposé dans un diff et appliqué seulement après confirmation
(`src/ai/`, `src/remediation/`) —, posture et contrôle CI/CD
(`src/posture/`, `src/cli/`). Leurs réglages sont décrits dans
**Paramètres → Extensions → Wazuh Security**.

Limites assumées :

- **aucun hook Git** n'est installé : un `push` depuis un terminal n'est
  pas vérifié ;
- l'analyse d'API est **statique** : une route montée dynamiquement ou un
  framework non pris en charge n'apparaît pas ;
- l'IA **explique, elle ne décide pas** : elle ne crée, ne supprime ni ne
  modifie aucun finding, et reste inactive sans clé côté backend ;
- l'extension ne parle **jamais** à Wazuh : les routes de supervision
  Wazuh du backend ne la concernent pas.

