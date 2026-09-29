# Wazuh Security — extension VS Code

Analyse de sécurité du code **pendant** le développement. À chaque
sauvegarde, le fichier est envoyé au backend Wazuh Supervision, qui
renvoie les problèmes détectés avec leur gravité, leur explication, leurs
conséquences possibles et une recommandation.

## Ce que l'extension fait, et ne fait pas

```
VS Code  →  extension  →  FastAPI /api/code/*     →  moteur de règles  →  SQLite
         ←   findings  ←

VS Code  →  extension  →  FastAPI /api/project/*  →  base OSV (réseau)  →  SQLite
         ←   findings  ←
```

Deux moteurs tournent **dans l'extension**, sur votre poste : la détection
de secrets et l'inventaire des dépendances. Lire un fichier pour y chercher
un secret est une opération locale ; l'envoyer à un serveur pour la même
raison n'en serait pas une. Seule une preuve **expurgée**
(`sk-proj-********`) traverse — jamais la valeur.

**Jamais** :

```
VS Code  →  Wazuh Manager API        ✗
VS Code  →  Wazuh Indexer            ✗
VS Code  →  OpenAI                   ✗
```

Le backend reste le seul détenteur d'informations d'identification et le
seul à sortir sur le réseau vers des tiers (OpenAI, base de
vulnérabilités). L'extension ne contient aucune clé et aucun mot de passe.

Elle porte en revanche deux moteurs **déterministes** depuis la phase 2 —
détection de secrets, inventaire de dépendances — précisément parce qu'ils
doivent rester locaux. Aucune IA n'y intervient : une IA pourra plus tard
expliquer une preuve, elle n'en créera jamais.

Elle ne modifie votre code qu'après une **confirmation explicite** de
votre part, et toujours par un `WorkspaceEdit` annulable par Ctrl+Z. Le
backend, lui, n'écrit jamais dans vos fichiers.

## Prérequis

- **VS Code 1.85** ou plus récent
- **Node.js 18+** et npm, pour compiler l'extension
- Le **backend Wazuh Supervision** en fonctionnement :

  ```powershell
  cd ..\backend
  .\.venv\Scripts\Activate.ps1
  uvicorn app.main:app --reload --port 8000
  ```

  Vérification : `http://127.0.0.1:8000/api/code/health` doit répondre
  `{"status":"ok", ...}`.

## Installation et compilation

```powershell
cd vscode-extension
npm install          # dépendances de développement uniquement
npm run compile      # build de développement (dist/extension.js)
```

Autres commandes :

| Commande            | Rôle                                              |
| ------------------- | ------------------------------------------------- |
| `npm run typecheck` | Vérification TypeScript seule, sans produire de build |
| `npm run watch`     | Recompilation à chaque modification des sources   |
| `npm run build`     | Vérification + build de production (minifié)      |
| `npm test`          | Tests unitaires (lanceur natif de Node)           |

Le build ne produit aucune erreur TypeScript : `tsconfig.json` est en mode
`strict`, avec `noUnusedLocals` et `noUnusedParameters`.

## Lancement en mode développement

1. Ouvrir le dossier `vscode-extension/` dans VS Code.
2. `npm install` puis `npm run compile`.
3. Appuyer sur **F5** (« Run Extension ») : une seconde fenêtre VS Code
   s'ouvre, avec l'extension chargée.
4. Ouvrir un projet dans cette fenêtre, puis sauvegarder un fichier
   Python, JavaScript, TypeScript, PHP ou Java.

Le canal **Affichage → Sortie → Wazuh Security** trace chaque analyse :
chemin du fichier, nombre de findings, version des règles. Le contenu du
fichier n'y apparaît jamais.

## Configuration

| Réglage                       | Défaut                  | Rôle |
| ----------------------------- | ----------------------- | ---- |
| `wazuhSecurity.backendUrl`    | `http://127.0.0.1:8000` | Adresse du backend d'analyse |
| `wazuhSecurity.autoScan`      | `true`                  | Active l'analyse automatique |
| `wazuhSecurity.scanOnSave`    | `true`                  | Analyse à chaque sauvegarde |
| `wazuhSecurity.syncOnStartup` | `true`                  | Reprend les findings encore ouverts au démarrage |
| `wazuhSecurity.aiEnrichment`  | `false`                 | Demande au **backend** un enrichissement IA. Sans effet tant que le backend n'a pas `CODE_AI_ENRICHMENT_ENABLED=true` et une clé OpenAI. |

`scanOnSave` désactivé, l'analyse reste disponible à la demande par la
commande **Wazuh Security: Scan Current File**.

## Actions sur un problème

Un clic sur l'ampoule (ou `Ctrl+.`) propose, selon le cas :

| Action | Effet |
| ------ | ----- |
| **Corriger** | Demande un correctif au backend, montre la ligne avant/après dans une fenêtre modale, et n'écrit **qu'après confirmation explicite**. |
| **Voir le détail** | Ouvre un panneau avec l'explication complète, les conséquences, les recommandations et le détail du score. |
| **Ignorer** | Marque le signalement comme faux positif, avec une raison facultative. |

La correction est appliquée par un `WorkspaceEdit` : elle est **annulable
par Ctrl+Z** et visible dans le diff Git. Le backend, lui, n'écrit jamais
dans vos fichiers — il décrit la modification, l'éditeur l'applique. Un
correctif est refusé si la ligne a changé depuis l'analyse.

Aucun finding n'est supprimé : « corrigé » et « ignoré » sont des états,
consultables ensuite via `GET /api/code/findings`.

## Analyse IA

Désactivée par défaut, des deux côtés. Elle demande :

- côté backend : `CODE_AI_ENRICHMENT_ENABLED=true` **et** une clé
  `OPENAI_API_KEY` ;
- côté extension : `wazuhSecurity.aiEnrichment` à `true`.

Tant que l'une des deux manque, **aucune requête ne part vers OpenAI** :
seules les règles déterministes s'appliquent.

Quand elle est active :

```
sauvegarde → règles (immédiat)         → diagnostics affichés
           → enrichissement IA (backend) → « Sécurité : analyse IA… »
           → event SSE code_finding      → diagnostic mis à jour
           → event SSE code_scan         → barre d'état finalisée
```

L'extension **n'appelle jamais OpenAI** et ne contient aucune clé : elle
demande l'enrichissement au backend, qui reste le seul à parler au modèle.
Si l'analyse IA échoue, les résultats des règles restent affichés et un
avertissement explique pourquoi — aucun résultat n'est inventé.

Le modèle peut conclure qu'une règle s'est trompée : le finding passe alors
en « ignoré (faux positif) » avec la raison, sans disparaître.

## La vue « Security »

Une icône de bouclier apparaît dans la barre d'activité. Elle ouvre deux
vues natives, sans webview ni framework :

```
SECURITY

Risk Overview
  Critical   2
  High       3
  Medium     1
  Low        0
  Total      6

Findings
  CRITICAL                    2
    SQL Injection             users.py:10
    Command Injection         tasks.py:44
  HIGH                        3
    Hardcoded Secret          config.py:22
  MEDIUM                      1
    Weak Cryptography         auth.py:83
```

Un clic sur un signalement ouvre le fichier, place le curseur sur la zone
concernée — la sélection couvre exactement ce que souligne le diagnostic —
et affiche la fiche détaillée.

Les deux vues affichent les findings **déjà produits** par `/api/code/*` :
aucune analyse n'a lieu dans l'éditeur. Elles se mettent à jour toutes
seules sur trois sources :

| Source | Effet |
| ------ | ----- |
| Réponse HTTP de `/api/code/scan` | Remplace les findings du fichier analysé. |
| Événement SSE `code_finding` | Remplace le finding enrichi par l'IA, recalcule les compteurs, rafraîchit la fiche ouverte. |
| `GET /api/code/findings` | Reprend l'historique du backend, sur demande (bouton ↻). |

### Le flux temps réel

**Une seule connexion** pour toute l'extension, ouverte à l'activation.
Elle n'écoute qu'un seul type d'événement, `code_finding` ; les alertes
Wazuh et les notifications IA circulent sur le même flux et sont écartées
par le client lui-même, sans même être décodées.

Le flux n'est jamais indispensable : le résultat du scan arrive par la
réponse HTTP, et l'analyse, les diagnostics et la barre d'état
fonctionnent sans lui.

En cas de coupure, la reconnexion est progressive — **1 s, 2 s, 4 s, 8 s,
16 s, puis 30 s au maximum** — et repart d'une seconde après une connexion
réussie. Aucune notification n'est affichée : une coupure du flux n'est
pas un incident pour l'utilisateur, seulement une ligne dans le canal de
sortie.

Ce qui transite n'est **jamais journalisé** : le flux transporte des
extraits de code, et pourrait transporter un secret détecté. Les traces se
limitent à l'état de la connexion et au nom des événements.

**L'état final d'une analyse ne vient pas du flux.** Quand un scan est
annoncé `pending` ou `analyzing`, l'extension relit l'analyse après
**30 s** par `GET /api/code/scans/{scan_uid}` — la route prévue pour cela
côté backend. Une seule source pour l'état terminal, qui fonctionne
identiquement flux ouvert ou flux coupé. Aucun contenu n'est retransmis :
le serveur répond depuis sa base. Si le modèle travaille encore, la
relecture est reportée.

À la fermeture (`deactivate`), le flux est interrompu, les minuteurs de
reconnexion, d'analyse et de relecture sont annulés, et les bulles
différées abandonnées : rien ne survit à l'extension.

> **`Last-Event-ID`** n'est pas utilisé. Le backend sait le lire, mais son
> rejeu puise dans la table des alertes et ne réémet que `event: alert` ;
> les `code_finding` sont publiés sans `id:` et n'y figurent pas. En
> envoyer un ne rattraperait aucun finding et déclencherait un rejeu
> d'alertes que l'extension jette. La reprise passe donc par le repli
> HTTP ci-dessus, sans toucher au contrat du backend.

### Au démarrage

L'extension reprend les signalements encore ouverts depuis
`GET /api/code/findings`, sans rien réanalyser. Trois filtres s'appliquent
dans cet ordre :

1. **une seule analyse par fichier** — l'historique en contient une par
   passage, et les reprendre toutes afficherait le même problème plusieurs
   fois ;
2. **les fichiers présents ici seulement** — la base est partagée avec
   l'interface web et d'autres postes ;
3. **les diagnostics exigent une correspondance exacte** — l'analyse
   d'origine est relue par `GET /api/code/scans/{scan_uid}` pour comparer
   son empreinte à ce qui est ouvert à l'écran. Si le fichier a changé
   depuis, il apparaît dans la vue Security mais **aucune ligne n'est
   soulignée** : la prochaine sauvegarde produira une analyse à jour.

Réglable par `wazuhSecurity.syncOnStartup` (activé par défaut).

Un finding annoncé par SSE pour un fichier jamais analysé depuis cet
éditeur est ignoré : `/api/stream` est partagé avec l'interface web, et la
vue ne doit pas afficher le code d'un autre poste.

## Commandes

| Commande                             | Rôle |
| ------------------------------------ | ---- |
| `Wazuh Security: Scan Current File`  | Analyse le fichier actif, même si `scanOnSave` est désactivé. Explique pourquoi si le fichier n'est pas analysable. |
| `Wazuh Security: Scan Workspace`     | Analyse tous les fichiers pris en charge du workspace (300 au maximum), avec une barre de progression annulable. |
| `Wazuh Security: Clear Findings`     | Vide la vue et les diagnostics. Le backend conserve son historique. |
| `Wazuh Security: Refresh Findings`   | Reprend les findings ouverts depuis `GET /api/code/findings`, en écartant ceux qui ne correspondent à aucun fichier du workspace. |
| `Wazuh Security: Analyze with AI`    | Relance l'analyse en demandant l'enrichissement IA **au backend**. N'apparaît que si le backend annonce l'IA active. |
| `Wazuh Security: Check Backend`      | Vérifie la connexion au backend et affiche sa version, son nombre de règles et l'état de l'enrichissement IA. |
| `Wazuh Security: Refresh Project Security` | Rétablit le contexte du projet : langages, frameworks, fichiers sensibles. |
| `Wazuh Security: Scan Project Security` | Relance la découverte **avec** la recherche de secrets et l'inventaire des dépendances, quels que soient les réglages d'analyse locale. Ne force pas l'appel à la base de vulnérabilités. |

Quatre commandes supplémentaires existent mais ne sont pas dans la palette :
elles prennent l'identifiant d'un finding et sont déclenchées par l'ampoule,
la vue ou la fenêtre de détail — `applyFix`, `dismissFinding`,
`showFindingDetail` (« View Issue ») et `openFinding`.

## Langages pris en charge

Cette version : **Python**, **JavaScript**, **TypeScript** (y compris JSX
et TSX), **PHP**, **Java**.

Prévus : Go, C#, Ruby, SQL, YAML. L'architecture est prête — il suffit
d'ajouter une ligne dans `SUPPORTED_LANGUAGES`
(`src/analysis/documentFilter.ts`) une fois les règles correspondantes
écrites côté backend.

## Fichiers jamais envoyés

Certains fichiers ne partent **jamais** vers le backend, quelle que soit
la configuration :

- `.env` et ses variantes ;
- clés privées et certificats : `*.pem`, `*.key`, `*.p12`, `*.pfx`,
  `*.jks`, `id_rsa`, `id_ed25519`… ;
- `.npmrc`, `.pypirc`, `.htpasswd`, `credentials`.

Sont également ignorés : `node_modules/`, `dist/`, `build/`, `out/`,
`.git/`, `.venv/`, `__pycache__/`, `vendor/`, `coverage/`, les fichiers
listés dans le `.gitignore` du projet (lecture simple, sans dépendance
supplémentaire), les documents non enregistrés, les fichiers vides et
ceux dépassant 400 Ko.

## Fonctionnement de l'analyse

1. Vous sauvegardez un fichier.
2. Le filtre vérifie que le fichier est pertinent et non sensible.
3. Un **anti-rebond de 800 ms** regroupe les sauvegardes rapprochées :
   dix `Ctrl+S` de suite ne déclenchent qu'une seule analyse.
4. L'empreinte SHA-256 du contenu est calculée et envoyée avec le
   document ; le backend la vérifie et refuse la requête si elle ne
   correspond pas.
5. La requête part de façon asynchrone : **VS Code n'est jamais bloqué**,
   même si le backend est lent.
6. Si le fichier est sauvegardé à nouveau pendant l'analyse, celle-ci est
   annulée et remplacée. Un résultat qui ne correspond plus au contenu
   affiché n'est jamais montré.
7. Les findings apparaissent dans l'éditeur (soulignement + panneau
   Problèmes) et la barre d'état affiche le résumé.

Le backend met en cache les résultats par `(chemin, empreinte)` :
sauvegarder sans avoir modifié le fichier ne relance aucune détection.

## Ce qui s'affiche

Chaque finding devient un diagnostic VS Code :

| Sévérité backend | Diagnostic VS Code |
| ---------------- | ------------------ |
| `CRITICAL`       | Error              |
| `HIGH`           | Error              |
| `MEDIUM`         | Warning            |
| `LOW`            | Information        |

Le survol affiche le titre, la gravité, les références CWE et OWASP,
l'explication, les conséquences possibles et la recommandation. Le code du
diagnostic renvoie vers la fiche CWE correspondante.

La barre d'état affiche `Sécurité : 1 critique, 2 élevées`, ou
`Sécurité : OK` quand rien n'est détecté.

### Les notifications, et pourquoi elles ne se répètent pas

Chaque niveau a son canal :

| Sévérité | Canal VS Code | Aspect |
| -------- | ------------- | ------ |
| `LOW`      | information | discret |
| `MEDIUM`   | avertissement | ⚠ standard |
| `HIGH`     | avertissement | marqué `⚠️` |
| `CRITICAL` | erreur | marqué `⛔`, le canal le plus visible |

La bulle contient le titre, le fichier, la ligne et la sévérité — **aucun
score** :

```
⛔ Security vulnerability detected

SQL Injection
users.py:10
Severity: CRITICAL

            [View Issue]  [Analyze with AI]
```

`View Issue` ouvre le fichier, place le curseur sur la ligne et affiche la
fiche. `Analyze with AI` demande l'enrichissement **au backend** — le
bouton n'apparaît que lorsque le backend annonce l'IA active.

Un problème n'est annoncé **qu'une fois**. La déduplication repose sur une
empreinte qui décrit le problème et non son évaluation :

```
SHA-256( file_path | rule_id | line | snippet )
```

Ni la sévérité, ni le score, ni `finding_uid` n'y entrent — `finding_uid`
est un UUID régénéré à chaque analyse, et la sévérité est précisément ce
que l'enrichissement IA fait changer.

| Situation | Notification |
| --------- | ------------ |
| Problème inédit | oui |
| Même fichier resauvegardé sans modification | non |
| Le même finding revient par SSE après enrichissement | non |
| L'IA revoit la sévérité à la baisse | non |
| L'IA **aggrave** la sévérité (MEDIUM → CRITICAL) | oui, une fois |
| La ligne fautive est modifiée ou déplacée | oui |
| Le finding est corrigé ou écarté | jamais |

Deux garde-fous de cadence complètent l'empreinte : une fenêtre de
regroupement de **500 ms** — une analyse qui remonte douze problèmes
produit une bulle nommant le plus grave et comptant les autres — et un
délai minimal de **15 s** entre deux bulles. L'échec d'un enrichissement
IA suit le même délai minimal, pour qu'un modèle indisponible ne produise
pas un avertissement par fichier.

### La fiche détaillée

La fenêtre de détail présente les données du backend, et rien d'autre :
titre, catégorie, gravité, score de risque, CWE, OWASP, fichier et ligne,
extrait, explication, pourquoi c'est dangereux, conséquences possibles,
recommandations, facteurs de risque, source, état et disponibilité d'un
correctif. **Un champ absent est annoncé « Non disponible. »** — aucun
contenu n'est inventé pour combler un vide.

C'est la seule webview de l'extension, et elle est verrouillée :

- CSP stricte — `default-src 'none'`, script et style autorisés par nonce
  uniquement, jamais par `unsafe-inline` ;
- aucune ressource externe, aucun accès au système de fichiers
  (`localResourceRoots: []`), aucun `command:` cliquable ;
- aucun secret, aucun jeton, aucune adresse de backend dans la page ;
- tout contenu dynamique est échappé — le code source remonté dans
  l'extrait n'est jamais interprété comme du HTML ;
- ses deux boutons se contentent de relayer les commandes existantes.

## Vérifier que tout fonctionne

Créez un fichier `test_securite.py` avec :

```python
def get_user(user_id):
    query = "SELECT * FROM users WHERE id=" + user_id
    return db.execute(query)
```

Sauvegardez. Attendu, moins d'une seconde plus tard :

- la ligne 2 soulignée en rouge ;
- au survol : « Requête SQL construite par concaténation », gravité
  **CRITIQUE**, `SQLI001 · CWE-89`, `A03:2021 - Injection`, l'explication,
  trois conséquences possibles et deux recommandations ;
- une notification « ⚠️ 1 vulnérabilité critique détectée dans
  test_securite.py » ;
- la barre d'état sur `Sécurité : 1 critique`.

Si rien n'apparaît, lancez **Wazuh Security: Check Backend** : le message
indique précisément ce qui bloque.

## Confidentialité

- Le contenu d'un fichier n'est envoyé qu'au moment de son analyse, et
  uniquement le fichier concerné : jamais le workspace entier.
- Il n'est **jamais** journalisé, ni stocké dans `globalState` ou
  `workspaceState`, ni conservé après la requête.
- Le workspace transmis est son **nom**, pas le chemin absolu du poste.
- Le code reçu n'est jamais exécuté, ni côté extension, ni côté backend.
- **La valeur d'un secret ne quitte jamais la machine.** La détection est
  locale, et seule une preuve expurgée — au plus 8 caractères de tête — est
  transmise. Elle est ré-expurgée par le backend avant écriture.
- Les fichiers sensibles (`.env`, `.pem`, `id_rsa`…) ne sont **pas lus**,
  pas même par le moteur de détection de secrets.
- L'inventaire des dépendances **n'installe rien et n'exécute rien** : il
  lit des fichiers texte.
- Ce qui sort vers la base de vulnérabilités publique : un nom de paquet,
  son écosystème, sa version. Réglable par
  `wazuhSecurity.project.vulnerabilityCheck`.

## État et suites

Analyse à la sauvegarde, diagnostics, barre d'état, notifications,
commandes. Enrichissement IA côté backend, flux SSE consommé réellement,
Quick Fix avec confirmation et `WorkspaceEdit`, action « Ignorer », fenêtre
de détail.

Contexte de projet : langages, frameworks, type, fichiers sensibles.

Sécurité du projet : détection de secrets, inventaire des dépendances,
analyse de vulnérabilités derrière une interface `VulnerabilityProvider`
(implémentation OSV). Les secrets et les dépendances vulnérables
apparaissent dans la vue **Findings** existante, triés avec le reste, et
dans le panneau **Problems**.

Surveillance continue : un fichier modifié sur disque — y compris hors de
l'éditeur, par exemple après un `git pull` — est détecté par un
`FileSystemWatcher` et réanalysé automatiquement, sans `Ctrl+S`. Voir le
README principal, §7 « Surveillance automatique des fichiers ».

Également présents : changements Git et vérification avant push (sans
hook Git), analyse statique des API, assistant IA de sécurité avec
correctif confirmé, posture et contrôle CI/CD (`node dist/ci-check.js`).

Non implémenté : intégration Wazuh (l'extension ne lui parle jamais),
interception d'un `push` lancé depuis un terminal.

Le flux SSE (`/api/stream`) reste **facultatif** : s'il est coupé,
l'analyse déterministe fonctionne intégralement et le résultat enrichi
reste consultable via `GET /api/code/scans/{scan_uid}`.

Non implémenté volontairement : rejeu SSE avec `Last-Event-ID`, historique
local des findings, correction multi-lignes.

## Tests

```powershell
npm test        # suites de test/*.test.ts, lanceur natif de Node
```

Ils couvrent les modules sans dépendance à `vscode` : empreinte, filtrage
des documents, client HTTP (traduction des codes
400/404/408/422/500/502/503, backend injoignable, réponse illisible,
annulation), découverte de projet, détection de secrets, inventaire des
dépendances et unification des findings. `fetch` est bouchonné et le
système de fichiers est injecté : aucun réseau, aucun backend, aucune clé
requise, aucune écriture sur disque.

Les tests de détection de secrets vérifient en priorité la garantie qui,
si elle tombait, rendrait la fonctionnalité pire que son absence : un
fichier contenant **toutes** les formes de clés reconnues est analysé, et
aucune valeur ne doit survivre dans aucun finding.

Les parties liées à l'API VS Code (diagnostics, ampoule, webview, barre
d'état) sont couvertes par le typecheck strict et se vérifient au lancement
F5, comme décrit plus haut.
