# Contexte de projet

Ce que l'agent sait du projet ouvert, comment il l'apprend, et ce qu'il
refuse d'apprendre.

Avant cette capacité, l'agent raisonnait **fichier par fichier** : il ne
pouvait pas répondre à « quels frameworks utilise ce projet ? », « où sont
ses fichiers sensibles ? », « qu'est-ce qui a changé ? ». Le contexte de
projet est la brique dont dépendent les phases suivantes.

---

## 1. Répartition des rôles

```
Extension                          Backend
---------                          -------
parcourt le disque                 ne lit aucun fichier
lit les manifestes                 classe, déduit, persiste
envoie des métadonnées             détient le contexte
aucune table de règles             toute la connaissance
                                   (langages, frameworks, motifs)
```

La logique de détection reste dans le backend, conformément à la règle du
projet. L'extension ne contient ni catalogue de frameworks, ni liste de
motifs sensibles côté contexte : elle décrit ce qu'elle voit.

Le backend ne parcourt jamais le disque du développeur — c'est un pilier du
projet, et il vaut aussi pour cette capacité.

---

## 2. Séquence

Trois échanges, dans cet ordre imposé :

```
1.  POST /api/project/discover           identité  →  project_uid
        { root_hash, project_name, discovery_version }

2.  parcours local                       index + manifestes
        (aucun échange réseau)

3.  POST /api/project/{uid}/index        index  →  contexte
        { files[], manifests[], git, discovered_count, truncated, warnings }

    GET  /api/project/{uid}/context      relecture  →  contexte
```

**Pourquoi l'enregistrement précède le parcours :** sans `project_uid`, un
index n'aurait nulle part où aller. Faire parcourir un monorepo de 20 000
fichiers pour découvrir ensuite que le backend est éteint serait du travail
perdu.

**Pourquoi deux routes et non une :** l'identité tient en trois champs et
doit répondre instantanément ; l'index peut porter des milliers d'entrées.
Les fusionner ferait d'un simple « bonjour, je suis ce projet » une requête
de plusieurs mégaoctets.

Toutes les routes exigent le jeton local, y compris la lecture : le
contexte décrit l'arborescence du projet et la liste de ses fichiers
sensibles.

---

## 3. Identité du projet

`project_uid` est attribué par le backend ; la clé de réconciliation est
`root_hash` = **SHA-256 du chemin racine normalisé**.

| Propriété | Conséquence |
| --- | --- |
| Stable | Le même dossier réouvert retrouve ses scans et ses findings |
| Distinct | `~/client-a/backend` ≠ `~/client-b/backend`, alors qu'ils s'appellent tous deux « backend » |
| Opaque | L'empreinte ne révèle ni l'utilisateur ni l'arborescence du poste |
| Local | Aucun appel réseau, aucun état à conserver |

Normalisations avant hachage : séparateurs en `/`, slash final retiré,
lettre de lecteur Windows en majuscule. La casse du **reste** du chemin est
conservée — l'uniformiser rendrait indistinguables deux dossiers réellement
différents sur un système sensible à la casse, ce qui serait un bug de
cloisonnement.

N'entre **pas** dans le calcul : le contenu d'un fichier, un manifeste, un
identifiant de dépôt Git. Un identifiant dérivé d'un `package.json`
changerait au premier renommage du paquet ; dérivé d'un secret, il serait
un secret.

---

## 4. Le modèle

```
ProjectSecurityContext
├── project_uid                identifiant attribué par le backend
├── project_name               nom du dossier, jamais son chemin
├── root_hash                  SHA-256 du chemin racine normalisé
├── status                     discovery | security_scan | analysis | ready | error
├── project_types[]            plusieurs à la fois si plusieurs s'appliquent
├── primary_language           le plus représenté, ou null
├── languages[]                { language, file_count, share, analysis_supported }
├── frameworks[]               { framework, evidence, source, confidence }
├── file_statistics            { discovered, indexed, source, manifests,
│                                configuration, tests, sensitive, truncated }
├── manifests[]                { path, kind, type, reason }
├── important_files[]          idem
├── configuration_files[]      idem
├── security_sensitive_files[] idem — chemin, type, raison. JAMAIS le contenu
├── git_repository_detected    booléen
├── git_remote_host            hôte seul, jamais l'URL
├── secret_statistics          décomptes de secrets — phase 2, §9
├── dependency_statistics      décomptes de dépendances — phase 2, §9
├── dependency_ecosystems[]    volumes par écosystème — phase 2, §9
├── vulnerability_statistics   décomptes + ÉTAT du fournisseur — phase 2, §9
├── warnings[]                 ce que la découverte n'a pas pu faire
├── last_discovery             horodatage ISO
└── discovery_version          version du format
```

Côté extension seulement, `LocalProjectView` ajoute `workspacePath` — le
chemin local, utile à l'infobulle et aux messages, qui **ne franchit jamais
la frontière HTTP**.

Aucun **score de sécurité** : la posture explicable, avec sa couverture,
appartient à la phase 8. Un chiffre sans son explication serait pris pour
un verdict. `status` décrit où en est le traitement, pas la qualité du
projet — `ready` signifie « la découverte a abouti », pas « ce projet est
sûr ».

### Stockage

Trois tables dans la base SQLite **existante** — aucune nouvelle
technologie, aucun fichier écrit dans le workspace du développeur :

```
projects         (project_uid, root_hash UNIQUE, display_name,
                  project_types, primary_language, languages, frameworks,
                  file_count, indexed_count, truncated, has_git,
                  git_remote_host, discovery_version, status, …)

project_files    (project_id, path, language, kind, size, content_hash,
                  mtime, indexed_at)   UNIQUE (project_id, path)

project_context  (project_id, payload, computed_at)
```

La colonne `code_scans.project_uid` est ajoutée par **migration additive** :
une colonne nullable ne détruit aucun finding existant, et un retour arrière
se contente de l'ignorer.

`GET /api/project/{uid}/context` **relit l'instantané** plutôt que de
recalculer : un second calcul pourrait différer du premier (plafonds,
version de classement), et l'utilisateur verrait deux réponses pour une
seule découverte.

L'index est **remplacé** à chaque soumission, pas fusionné : un fichier
supprimé du projet doit disparaître du contexte, sinon le décompte affiché
cesse de décrire le projet réel.

---

## 5. Détection

### Langages

Déduits des extensions, sur les fichiers **source et de test réels** — un
`.md` compté comme un langage gonflerait les proportions sans rien dire du
code.

Reconnus : Python, JavaScript, TypeScript, Java, PHP, Go, C#, Ruby, SQL.

`analysis_supported` distingue « présent dans ce projet » de « couvert par
le moteur de règles ». Un projet Go voit Go listé avec
`analysis_supported: false`, et l'interface le signale : annoncer une
couverture inexistante tromperait l'utilisateur sur sa propre exposition.

Un langage n'est **jamais** listé parce qu'il est pris en charge — seulement
parce qu'un fichier l'atteste.

### Frameworks

Aucun framework sans preuve. Deux sources, deux niveaux de confiance :

| Preuve | Confiance | Pourquoi pas davantage |
| --- | --- | --- |
| Dépendance déclarée dans un manifeste | 0,9 | Un manifeste peut déclarer une dépendance que le code n'utilise plus, et cette phase ne lit pas le code |
| Fichier de configuration dédié | 0,7 | Un `angular.json` peut survivre au retrait d'Angular |

La correspondance est **exacte**, jamais une sous-chaîne : `react-scripts`
est un outil de build et ne prouve pas React ; `flask-cors` est une
extension et ne prouve pas une application Flask. Accepter ces noms
produirait des détections fausses sur des projets très courants.

`evidence` et `source` accompagnent la détection **jusqu'à l'écran** :
l'utilisateur peut vérifier, et contester.

Reconnus : React, Angular, Vue, Svelte, Next.js, Nuxt, Express, NestJS,
Koa, Fastify, hapi, FastAPI, Flask, Django, Starlette, Tornado, aiohttp,
Pyramid, Spring, Spring Boot, Quarkus, Micronaut, Laravel, Symfony, Slim,
Ruby on Rails, Sinatra, Gin, Echo, Fiber, ASP.NET, ASP.NET Core.

### Types de projet

Une **liste**, pas une catégorie unique : un dossier contenant un frontend
React et un backend FastAPI est les deux, et le forcer dans une case
perdrait l'information qui compte pour la suite — quelles surfaces
analyser.

`Frontend`, `Backend`, `Full-stack`, `Python application`,
`Node.js / web application`, `Java application`, `.NET application`,
`PHP application`, `Go application`, `Ruby application`, `Monorepo`,
`Containerised / infrastructure-as-code`, `Unknown`.

`Unknown` est renvoyé plutôt qu'un type deviné : un type inventé
orienterait à tort toutes les phases suivantes.

### Classement des fichiers

L'ordre des contrôles porte une décision : **le classement sensible passe
en premier**, avant même le manifeste et la configuration. Un `.env`
pourrait passer pour une configuration ; s'il atterrissait dans
`configuration_files`, il rejoindrait une liste où les phases suivantes
s'autorisent à lire.

```
1. sensitive       .env, *.pem, *.key, id_rsa, .npmrc, credentials.*, secrets.*
2. manifest        package.json, requirements.txt, pom.xml, go.mod, *.csproj…
3. infra / config  Dockerfile, docker-compose, *.tf, .github/workflows/,
                   tsconfig.json, vite.config.*, .gitignore…
4. test            tests/, *_test.py, *.spec.ts, __tests__/…
5. source          d'après l'extension
6. documentation   README.md, SECURITY.md, LICENSE, CODEOWNERS
7. other
```

Les tests passent **avant** la source : un finding dans un test ne porte
pas le risque d'un finding en production.

---

## 6. Déclencheurs

| Événement | Comportement |
| --- | --- |
| Ouverture du workspace | Découverte en arrière-plan, si `wazuhSecurity.project.discoverOnStartup` (défaut : activé) — **après** le contrôle du backend, puis reprise de l'historique filtrée par projet (`project/startup.ts`) |
| Changement de dossier du workspace | Contexte précédent oublié, puis nouvelle découverte |
| Commande « Refresh Project Security » | Découverte, avec compte rendu à l'écran |
| Sauvegarde ou modification d'un fichier | **Phase 3** — voir §10 : le seul fichier touché est réanalysé, jamais le projet |

La sauvegarde d'un fichier ne relance toujours **pas** la découverte :
relancer un parcours complet à chaque sauvegarde serait exactement ce
qu'il ne faut pas faire. La phase 3 réanalyse le fichier, et reconstitue
le lot soumis depuis ce que le dernier parcours avait constaté.

---

## 7. Interface

Une `TreeView` native de plus dans le conteneur existant — même
architecture que les vues Risk Overview et Findings, aucune dépendance
ajoutée, aucun HTML.

```
SECURITY
├── Project                          ← nouvelle vue
│   Project              MonApplication
│   Statut               Prêt
│   Type de projet       Full-stack, Frontend, Backend
│   Languages            python, typescript
│     python             120 fichiers · 55 %
│     typescript         98 fichiers · 45 %
│   Frameworks           FastAPI, React
│     FastAPI            dépendance « fastapi » déclarée — requirements.txt
│     React              dépendance « react » déclarée — package.json
│   Files                428 indexés
│   Fichiers sensibles   3
│     .env               peut contenir des identifiants
│   Dépôt Git            ✓ Détecté
│   Dernière découverte  22:03
├── Risk Overview                    ← inchangée
└── Findings                         ← inchangée
```

Ce que la vue signale par la couleur autant que par le texte : un index
tronqué (orange), un langage sans règles disponibles (jaune), les fichiers
sensibles (orange). Les avertissements apparaissent dépliés quand il y en
a.

Ce que la vue ne montre **pas** : aucun score, aucune note, aucun contenu
de fichier — le contrat n'en transporte pas.

---

## 8. Réglages

| Réglage | Défaut | Portée |
| --- | --- | --- |
| `wazuhSecurity.project.discoverOnStartup` | `true` | fenêtre |
| `wazuhSecurity.backendUrl` | `http://127.0.0.1:8000` | **machine** |
| `wazuhSecurity.allowRemoteBackend` | `false` | **machine** |

Côté backend (`backend/.env`) :

| Variable | Défaut | Rôle |
| --- | --- | --- |
| `PROJECT_MAX_INDEXED_FILES` | `20000` | Plafond de l'index, appliqué aussi côté serveur |
| `PROJECT_MAX_LISTED_FILES` | `200` | Plafond par liste dans le contexte renvoyé |

Le plafond est appliqué **des deux côtés** : l'extension a le sien, et le
backend ne fait pas confiance à la borne du client.

---

## 9. Sécurité du projet (phase 2)

La découverte constate ce qu'est le projet. La phase 2 y ajoute ce qu'il
**contient de risqué** : des secrets écrits en dur et des dépendances
vulnérables.

### 9.1 Un seul parcours, trois moteurs

Les analyses de sécurité se greffent sur le parcours existant plutôt que
d'en lancer un second :

```
walk()  ──►  empreinte du fichier ──┬──►  index (phase 1)
                                    └──►  détection de secrets (phase 2)

        ──►  lecture d'un manifeste ─┬──►  noms de dépendances (phase 1)
                                     └──►  inventaire versionné (phase 2)
```

La découverte lit **déjà** chaque fichier éligible pour en calculer
l'empreinte, et chaque manifeste pour en extraire des noms. Rendre ce texte
au moment où il est en main évite un second parcours complet du disque —
sur un monorepo, la différence est de plusieurs minutes.

Le couplage est inversé : `projectDiscovery.ts` ne connaît aucune logique
de sécurité. Il expose des crochets (`onFileText`, `onManifestText`) et
l'appelant décide de ce qu'il en fait. Le module reste testable seul, et la
détection de secrets ne peut pas s'infiltrer dans le parcours.

**Ce que les crochets ne changent pas :** `onFileText` n'est appelé que
pour les fichiers réellement lus. Un `.env`, un binaire ou un fichier de
plus de 2 Mo ne passent jamais par là, parce qu'ils ne sont pas ouverts. La
règle « ces fichiers ne sont jamais lus » n'est pas relâchée.

### 9.2 Séquence complète

```
1.  POST /api/project/discover           identité   →  project_uid
2.  parcours local                        index + secrets + inventaire
                                          (aucun échange réseau)
3.  POST /api/project/{uid}/index         index      →  contexte
4.  POST /api/project/{uid}/secrets       constats   →  findings + stats
5.  POST /api/project/{uid}/dependencies  inventaire →  findings + stats
                                          (le backend interroge OSV ici)

    GET  /api/project/{uid}/findings      relecture  →  findings unifiés
```

**Pourquoi la sécurité vient après l'index :** un contexte de projet établi
vaut par lui-même. Un balayage de secrets refusé par le backend ne doit pas
faire perdre la découverte.

**Pourquoi deux routes et non une :** un balayage de secrets et un
inventaire de dépendances échouent pour des raisons différentes, et l'échec
de l'un ne doit pas annuler l'autre. Les secrets sont soumis en premier :
c'est la partie la plus urgente.

### 9.3 Les quatre champs ajoutés au contexte

```
ProjectSecurityContext
├── … (phase 1, inchangé)
├── secret_statistics          { total, critical, high, medium, low,
│                                files_with_secrets, scanned_files,
│                                truncated, engine, last_scan }
├── dependency_statistics      { total, direct, transitive, vulnerable,
│                                unverified, manifests_read, truncated,
│                                last_inventory }
├── dependency_ecosystems[]    { ecosystem, total, direct, vulnerable,
│                                verified }
└── vulnerability_statistics   { total, critical…low, packages_affected,
                                 packages_checked, packages_unverified,
                                 provider, provider_status, conclusive,
                                 message, last_check }
```

**Des nombres, jamais des valeurs.** Aucun de ces types ne peut porter la
valeur d'un secret : ils ne contiennent que des entiers, des libellés
d'écosystème et un état de fournisseur. Le détail vit dans les findings.

Trois champs méritent d'être lus attentivement :

- **`unverified`** — les dépendances que personne n'a pu vérifier : version
  non figée, écosystème non couvert, fournisseur muet. Elles ne sont
  **jamais** comptées comme saines ;
- **`provider_status`** et **`conclusive`** — sans eux, un `total: 0` se
  lirait comme un feu vert alors qu'il peut signifier « la base n'a pas
  répondu » ;
- **`last_scan: null`** — signifie « jamais analysé », pas « aucun secret ».
  L'interface écrit les deux différemment.

### 9.4 Persistance des statistiques

Les statistiques sont écrites dans **l'instantané** du contexte, pas
recalculées à la lecture. La raison tient à un cas précis : l'état du
fournisseur de vulnérabilités n'est pas reconstituable depuis la base.
« Zéro vulnérabilité parce que la base a répondu » et « zéro parce que
personne n'a répondu » donneraient les mêmes lignes en table. Conserver
`provider_status` tel qu'il était au moment du balayage est la seule façon
de ne pas perdre cette distinction — qui est précisément celle qui compte.

Une re-soumission de l'index **reprend** les statistiques précédentes :
ré-indexer des fichiers ne dit rien de nouveau sur les secrets, et les
remettre à zéro afficherait « 0 secret » à un projet qui en a — le plus
trompeur des deux mensonges possibles.

### 9.5 Stockage

Deux tables supplémentaires dans la base SQLite existante :

```
security_findings      (finding_id UNIQUE, project_uid, category, severity,
                        confidence, title, description, file_path,
                        line_start, line_end, evidence EXPURGÉE,
                        remediation, reference_links, detection_engine,
                        fingerprint, status, created_at, updated_at)
                       UNIQUE (project_uid, category, fingerprint)

project_dependencies   (project_id, name, ecosystem, version, direct,
                        manifest, source, vulnerable, verified, indexed_at)
                       UNIQUE (project_id, ecosystem, name, version, manifest)
```

Aucune clé étrangère vers la chaîne Wazuh, et aucun appel Wazuh dans le
code qui les remplit.

**`fingerprint`** est l'empreinte stable d'un finding — catégorie, moteur,
fichier, ligne, type de secret ou identifiant de vulnérabilité. Elle ne
porte **aucune valeur de secret** : rien dans la base ne permet de remonter
à ce qui a été détecté.

Elle sert à un comportement précis : un second balayage reconnaît le même
problème, conserve son `status` et son `created_at`, et supprime ce qui a
disparu. Sans elle, chaque balayage ferait réapparaître ce que
l'utilisateur a écarté comme faux positif — le plus sûr moyen de rendre un
outil de sécurité inutilisable, parce qu'on cesse de le lire.

**`verified`** distingue « la base a répondu, rien pour ce paquet » de
« personne n'a regardé ». Sans ce drapeau, les deux seraient indiscernables
en table.

### 9.6 Réglages

| Réglage | Défaut | Ce qu'il décide |
| --- | --- | --- |
| `wazuhSecurity.project.secretDetection` | `true` | Recherche de secrets, **entièrement locale** |
| `wazuhSecurity.project.dependencyAnalysis` | `true` | Inventaire, **lecture de manifestes seule** |
| `wazuhSecurity.project.vulnerabilityCheck` | `true` | Comparaison à la base publique, **via le backend** |

Le troisième est séparé des deux autres pour une seule raison : c'est le
seul qui fait sortir quelque chose de la machine. On peut vouloir
l'inventaire sans l'appel externe.

Côté backend (`backend/.env`) :

| Variable | Défaut | Rôle |
| --- | --- | --- |
| `SECRET_DETECTION_ENABLED` | `true` | Réception des balayages de secrets |
| `SECRET_MAX_FINDINGS` | `500` | Plafond serveur, annoncé quand il mord |
| `DEPENDENCY_INVENTORY_ENABLED` | `true` | Réception des inventaires |
| `PROJECT_MAX_DEPENDENCIES` | `3000` | Plafond serveur de l'inventaire |
| `DEPENDENCY_VULNERABILITY_ENABLED` | `true` | **Seule sortie réseau** de la phase 2 |
| `VULNERABILITY_PROVIDER` | `osv` | Implémentation de `VulnerabilityProvider` |
| `OSV_API_URL` | `https://api.osv.dev` | Adresse de la base publique |
| `OSV_TIMEOUT_SECONDS` | `12` | Délai au-delà duquel l'état devient `timeout` |
| `OSV_MAX_PACKAGES` | `1000` | Au-delà, le résultat est annoncé `partial` |

Une capacité désactivée répond **503**, jamais une liste vide : une liste
vide se lirait « rien à signaler ».

### 9.7 Commande

**« Wazuh Security: Scan Project Security »** relance la découverte avec
les deux analyses explicitement demandées, quels que soient les réglages
d'analyse locale. Elle ne force **pas** l'interrogation de la base publique
— interroger un service externe reste une décision distincte, et une
commande de balayage ne vaut pas consentement à faire sortir la liste des
dépendances de la machine.

---

## 10. Surveillance continue (phase 3)

Les phases 1 et 2 répondent quand on leur demande. La phase 3 fait de
l'extension un **agent** : il regarde le dossier, et quand un fichier
bouge, il réanalyse ce fichier — **pas** le projet.

### 10.1 Le chemin d'un changement

```
FileSystemWatcher                 create / change / delete
     |
     v
classifyChange()                  dossier exclu ? binaire ? sensible ?
     |                            code, manifeste, ou simple texte ?
     v
SignatureCache                    taille -> date -> empreinte
     |                            inchangé ? on s'arrête ici
     v
ScanQueue                         anti-rebond, dédoublonnage, priorité,
     |                            concurrence bornée, contre-pression
     v
moteurs EXISTANTS                 ScanController    -> /api/code/scan
                                  scanForSecrets    -> .../secrets
                                  parseDependencies -> .../dependencies
     |
     v
findings EXISTANTS                relus chez le backend, publiés par le
                                  même chemin qu'un balayage complet
```

Aucune seconde architecture de findings n'est créée. Le surveillant ne
fabrique aucun finding : il alimente les moteurs de la phase 2, et la
vue, les diagnostics et les bulles restent ceux des phases précédentes.

### 10.2 Ce qui déclenche quoi

L'ordre des contrôles reprend celui du classement de la phase 1 — le
**sensible passe en premier**, avant le manifeste et le code.

| Fichier | Analyse déclenchée |
| --- | --- |
| Dossier exclu, `.gitignore`, hors du dossier ouvert | Aucune |
| `.env`, `*.pem`, `id_rsa`, `credentials.*` | **Aucune — jamais lu.** Journalisé par son chemin |
| Binaire, média, archive | Aucune |
| `package.json`, `requirements.txt`, lockfile... | Dépendances **+** secrets |
| `.py`, `.js`, `.ts`, `.php`, `.java` | Code **+** secrets |
| Tout autre fichier texte | Secrets seulement |

Un `credentials.json` ressemble à un manifeste ; s'il était classé comme
tel, il serait **lu**. C'est pourquoi le contrôle sensible passe devant.

Le classement par extension ne décide que d'une chose : vaut-il la peine
d'ouvrir ce document ? `documentFilter.evaluate()` reste **la** référence
pour ce qui part au backend.

### 10.3 Éviter le travail inutile

Trois niveaux, du moins cher au plus cher, sur le triplet que la phase 1
indexe déjà :

```
taille      un octet de différence suffit à conclure « changé »
date        taille identique + date identique   ->  rien n'a bougé
empreinte   date différente, contenu identique ->  rien n'a bougé
```

Le troisième niveau couvre un geste très banal : `Ctrl+S` sans avoir rien
tapé, un formateur qui réécrit à l'identique, un `git checkout` qui
restaure la même version. Sans lui, chacun déclencherait une analyse.

Sans empreinte des deux côtés, on conclut « changé » : un fichier manqué
à tort est un angle mort de sécurité, un fichier réanalysé à tort coûte
une requête.

### 10.4 La file

| Garantie | Comment elle est tenue |
| --- | --- |
| Anti-rebond | `submit` reprogramme le minuteur du chemin ; dix `Ctrl+S` = un travail |
| Aucun doublon | Un chemin n'a jamais deux entrées ; les analyses demandées **fusionnent** |
| Un seul à la fois | Un chemin déjà en cours n'est pas relancé en parallèle ; le travail en vol est annulé |
| Annulation | Chaque exécution reçoit un `AbortSignal` réellement utilisé |
| Concurrence bornée | Deux travaux de front — saturer le backend dégraderait l'analyse à la demande |
| Contre-pression | Plafond de 500 travaux ; au-delà, les **ordinaires les plus anciens** sont abandonnés, jamais un prioritaire |
| Priorité | Le fichier sauvegardé passe devant la rafale de fond |
| Jamais bloquant | Rien n'est attendu sur le fil de l'interface |

Une annulation n'est **pas** une erreur : elle ne fait jamais passer la
barre d'état en `ERROR`. Un abandon par contre-pression est toujours
journalisé — une file qui perd des travaux en silence ferait croire à une
surveillance complète qui n'a pas eu lieu.

### 10.5 Analyse incrémentale sans lot partiel

Les routes de sécurité **réconcilient** : le backend aligne sa base sur ce
que le balayage lui annonce, conserve les décisions de l'utilisateur par
empreinte, et supprime ce qui a disparu. C'est ce qui empêche un faux
positif écarté de revenir à chaque balayage.

Conséquence directe : soumettre le seul fichier modifié **effacerait les
constats de tous les autres**.

`SecurityBaseline` conserve donc ce que le dernier parcours a constaté,
par fichier et par manifeste. Un fichier modifié remplace sa seule entrée,
et le lot complet est reconstitué **sans toucher au disque**. Le backend
reçoit un balayage cohérent, sa réconciliation fonctionne comme avant, et
rien n'est relu.

Le registre est alimenté par les accumulateurs de la phase 2, au moment où
le détail est déjà en main : `SecretScanAccumulator.perFile()` et
`DependencyInventoryAccumulator.perManifest()` sont des ajouts **purement
additifs** — `result()` ne change pas d'un octet.

**Rien n'est soumis sans parcours de référence.** Tant qu'aucune
découverte n'a abouti dans cette session, le registre est vide, et un lot
vide annoncerait « ce projet n'a plus aucun secret ». La surveillance
attend, et le journal le dit.

Une soumission ne réveille que le moteur concerné : un `.py` modifié ne
resoumet pas l'inventaire des dépendances, donc ne réinterroge pas la base
publique de vulnérabilités. Le réglage de l'utilisateur autorise cette
sortie réseau parce qu'elle apprend quelque chose — la déclencher pour
rien serait en abuser.

### 10.6 Notifications

Aucun nouveau mécanisme : le `NotificationLedger` de la phase 2
dédoublonne déjà par empreinte — chemin, règle, ligne, extrait — et
ignore la gravité, de sorte qu'un même problème n'est annoncé qu'une fois.

Le surveillant republie **tous** les findings du projet à chaque cycle,
parce qu'une soumission de secrets seule ne renvoie que des secrets et
ferait disparaître les dépendances vulnérables de la vue. Le registre tait
ce qu'il a déjà annoncé ; seuls passent :

- un finding **nouveau** ;
- un finding dont la gravité **augmente** ;
- un secret **déplacé** — le backend le recrée, et la décision précédente
  portait sur ce qui était là, pas sur ce qui y est maintenant.

Une gravité qui redescend, un finding écarté, un lot identique au
précédent : silence.

### 10.7 Barre d'état

Un élément dédié, distinct du résumé de scan. Le premier répond
« qu'a-t-on trouvé dans ce fichier ? », celui-ci « l'agent regarde-t-il
encore ? » — les confondre ferait disparaître l'état de surveillance dès
qu'un scan affiche un résultat.

| État | Affichage | Signification |
| --- | --- | --- |
| `READY` | oeil · « Surveillance : prête » | Le projet est surveillé, rien en attente |
| `ANALYZING` | roue · « Surveillance : analyse... » | Des fichiers modifiés sont en cours d'analyse |
| `ERROR` | alerte · « Surveillance : erreur » | La dernière analyse n'a pas abouti ; les résultats précédents restent affichés |

L'état canonique est repris tel quel dans l'infobulle : c'est ce nom qui
apparaît dans le journal. Une réussite efface l'erreur ; une rafale ne
produit que deux transitions, pas quarante.

### 10.8 Cloisonnement

Le registre et le cache d'empreintes décrivent **un** projet. Au changement
de dossier ouvert, les deux sont oubliés avant toute redécouverte : les
conserver ferait soumettre les constats du précédent sous l'identifiant du
suivant.

Le `project_uid` est résolu **au démarrage de chaque travail**, et vérifié
à nouveau avant publication : si le dossier a changé pendant
l'aller-retour, le résultat est écarté plutôt qu'affiché sous le nom d'un
autre projet.

Un chemin hors du dossier ouvert n'est jamais retenu, même si l'éditeur
signale le changement.

### 10.9 Réglages

| Réglage | Défaut | Ce qu'il décide |
| --- | --- | --- |
| `wazuhSecurity.monitoring.enabled` | `true` | Surveillance continue. Désactivé, l'extension retrouve exactement le comportement de la phase 2 |
| `wazuhSecurity.monitoring.debounceMs` | `1200` | Attente avant analyse. Borné à `[200, 10000]`, relu à chaque usage |

Les analyses de la surveillance obéissent aux **mêmes réglages** que le
reste — `autoScan`, `project.secretDetection`,
`project.dependencyAnalysis`, `project.vulnerabilityCheck`. La surveillance
n'est pas une porte dérobée pour faire tourner ce que l'utilisateur a
désactivé.

Aucun réglage backend : la phase 3 n'ajoute **aucune route**.

### 10.10 Limites connues

- **Un fichier sensible modifié n'est pas reclassé.** Un `.env` créé ou
  modifié est journalisé, jamais lu ; sa prise en compte dans les
  statistiques demande un « Scan Project Security ». La règle « ces
  fichiers ne sont jamais lus » ne cède pas parce qu'un fichier vient de
  bouger.
- **Le registre ne survit pas à la session.** Au redémarrage de l'éditeur,
  la surveillance attend la première découverte avant de pouvoir
  soumettre. Les findings, eux, sont repris du backend et restent
  affichés.
- **Le plafond de la phase 2 reste celui du registre.** Un projet dont le
  balayage initial a été tronqué reste tronqué : la surveillance ne
  découvre pas les fichiers que le parcours n'a pas retenus.
- **Un renommage est vu comme une suppression suivie d'une création.**
  C'est correct, mais cela produit deux travaux au lieu d'un.
- **Un fichier modifié éditeur fermé garde ses findings de code** jusqu'à
  sa prochaine analyse (sauvegarde, « Scan Workspace »). La découverte
  d'ouverture ne relance pas l'analyse de code ; le contrôle CI, lui,
  réanalyse tout.

---

## 11. Sécurité des changements Git (phase 4)

Les phases 2 et 3 répondent à « que contient ce projet de risqué ? ».
La phase 4 répond à une question différente, et plus utile au moment de
livrer : **« ce que je viens d'écrire introduit-il un problème ? »**

### 11.1 Aucune commande `git`

Tout passe par l'API de l'extension Git de VS Code. Aucun `child_process`,
aucun `exec`, aucun terminal. Un test parcourt le code source de
`src/git/` et refuse toute importation de `child_process`.

Ce n'est pas une préférence de style. Lancer `git` revient à exécuter un
binaire choisi par le `PATH` du poste, dans un dossier qui vient d'être
cloné, avec une configuration (`core.fsmonitor`, `core.pager`, les hooks)
que le dépôt lui-même peut fixer. Un dépôt hostile obtiendrait
l'exécution de code par le seul fait qu'on l'analyse — et un agent de
sécurité qui se fait exécuter par ce qu'il inspecte n'en est plus un.

### 11.2 Le chemin d'une analyse

```
vscode.git                    branche, remote, fichiers modifiés
     |                        diffWithHEAD() / diffIndexWithHEAD()
     v
VsCodeGitWorkspace            SEULE pièce qui importe `vscode`
     |                        l'URL du remote est expurgée ICI
     v
diffParser                    diff unifié -> lignes ajoutées
     |                        le contenu des lignes est JETÉ
     v
secretScanner (phase 2)       sur les seuls fichiers modifiés
     |
     v
changeAttribution             introduit / préexistant
     |
     v
prePushPolicy                 off / warn / block
```

Tout ce qui **décide** est pur et testé sans éditeur. L'adaptateur
`vscodeGitWorkspace.ts` ne contient aucune décision : il traduit l'état
du dépôt dans des types neutres, et s'arrête là.

### 11.3 Aucune seconde architecture de findings

La phase 4 ne crée **aucun** finding et n'ajoute **aucune** route backend.
Elle **classe** les `SecurityFinding` que les phases 2 et 3 ont déjà
produits :

| | |
| --- | --- |
| **Introduit** | Les lignes du finding croisent une ligne que le changement ajoute |
| **Préexistant** | Tout le reste |

Le classement vit à côté du finding, dans `AttributedFinding` ; le
finding lui-même n'est jamais modifié. C'est ce qui permet à la vue, aux
diagnostics et aux bulles de continuer à travailler sur le type qu'ils
connaissent.

Un secret détecté localement dans un fichier non encore soumis est
exprimé dans **le même** `SecurityFinding`. Il sert à la décision avant
`push` et au résumé ; il n'est ni persisté ni publié dans le registre —
c'est la soumission de la phase 2 qui fait cela, par son chemin.

### 11.4 Le biais de l'attribution, et pourquoi il va dans ce sens

En cas de doute — ligne inconnue, finding sans fichier, diff illisible —
le verdict est **préexistant**.

Le biais est délibéré et va dans un seul sens. Se tromper vers
« introduit » ferait bloquer des `push` pour des problèmes que le
développeur n'a pas causés, et la protection serait désactivée dans la
semaine. Se tromper vers « préexistant » laisse passer un problème qui
**reste signalé par ailleurs**, dans la vue et dans « Problems ».

Autrement dit : cette attribution décide de **ce qui interrompt**, pas de
ce qui est signalé. Rien n'est jamais masqué par elle.

Cas particuliers :

- **fichier entièrement nouveau** — tout ce qu'il porte est introduit ;
- **fichier non suivi** — Git ne le connaît pas, aucun diff ne le
  mentionne. Il est traité comme ajouté, parce que c'est exactement le
  cas où un secret se glisse ;
- **fichier supprimé** — rien à y attribuer ;
- **finding sans ligne** (une dépendance déclarée dans un manifeste
  modifié) — préexistant : on ne sait pas situer la ligne.

### 11.5 Protection avant push

| Mode | Comportement |
| --- | --- |
| `off` | Aucune vérification |
| `warn` | **Défaut.** Prévient, laisse passer |
| `block` | Demande une confirmation explicite |

`warn` est le défaut parce qu'un outil de sécurité qui bloque sans qu'on
le lui ait demandé est désinstallé, pas corrigé.

Quatre règles :

1. **Seul ce qui est introduit compte.** Un problème préexistant ne bloque
   jamais ;
2. **Seules les gravités `CRITICAL` et `HIGH` interrompent.** Une
   interruption sur un `LOW` coûte plus d'attention qu'elle n'en mérite,
   et dévalue les suivantes ;
3. **Le blocage a toujours une sortie.** « Pousser quand même » est
   proposé à chaque blocage, et le contournement est journalisé. Un test
   vérifie cet invariant, parce que c'est la garantie la plus facile à
   perdre au fil des retouches. Une protection sans échappatoire empêche
   de livrer un correctif urgent, et se contourne alors par la ligne de
   commande — donc sans laisser de trace ;
4. **L'échec est ouvert.** Délai dépassé, dépôt illisible, moteur en
   panne : la décision est `allow`, marquée `degraded`, et l'utilisateur
   en est averti. Un agent de sécurité qui empêche de travailler quand il
   tombe en panne est un agent qu'on retire.

**Aucun hook Git n'est installé**, dans aucun mode, ni au démarrage ni sur
proposition. Écrire dans `.git/hooks` reviendrait à installer du code
exécutable dans le dépôt de l'utilisateur sans demande explicite, et un
hook posé en silence donne le sentiment d'être protégé partout alors
qu'il ne l'est que sur ce poste et ce clone. La vérification est lancée
par la commande « Wazuh Security: Check Changes Before Push ». Un test
refuse toute écriture de fichier dans `src/git/`.

### 11.6 Rapidité : sous trois secondes

La vérification ne fait **aucun aller-retour réseau** :

- le diff vient de l'API Git ;
- la recherche de secrets tourne en local, sur les **seuls fichiers
  modifiés** — quelques expressions régulières ;
- les findings de projet sont ceux que le registre détient déjà.

Le budget (`git.budgetMs`, 2500 ms par défaut) est un vrai compte à
rebours, vérifié entre chaque étape. L'horloge est injectable, ce qui
rend le dépassement testable sans attendre.

### 11.7 Mode réduit

Au-delà de `git.maxChangedFiles` (50 par défaut), seuls les premiers
fichiers sont analysés, dans un ordre **stable** — deux analyses du même
état retiennent les mêmes fichiers.

Le résumé l'annonce, en texte et par la couleur. Un `git checkout` de
branche peut toucher des milliers de fichiers ; prétendre les vérifier
tous en quelques secondes serait faux, et annoncer la couverture partielle
est la seule option honnête.

### 11.8 Métadonnées de remote

Une URL de remote est un endroit où les jetons se cachent :
`https://x-access-token:ghp_xxx@github.com/org/repo` est une forme
ordinaire, produite par les intégrations CI et plusieurs gestionnaires
d'identifiants.

`remoteUrl.ts` est la seule pièce qui manipule une URL brute, et
l'expurgation est appliquée **à la frontière**, dans l'adaptateur. En
aval, personne n'a accès à l'URL complète — donc personne ne peut la
journaliser, même par accident. Seul l'hôte circule.

En cas de doute, la règle est de **renvoyer moins** : une URL qu'on ne
sait pas lire devient `null`, jamais une chaîne transmise en espérant
qu'elle soit inoffensive.

### 11.9 Surveillance de l'état du dépôt

`repository.state.onDidChange` se déclenche à chaque frappe dans un
fichier suivi. Deux garde-fous, dans cet ordre :

1. **Empreinte d'état** — branche, commit, volumétrie. Un événement qui
   ne change pas l'empreinte est abandonné sans rien faire ;
2. **Anti-rebond** — les événements survivants sont regroupés.

Un changement de branche recalcule **l'attribution seulement**. Aucune
découverte de projet n'est relancée : c'est précisément le moment où un
parcours complet coûterait le plus cher. La garantie est structurelle —
un test vérifie que `src/git/` n'a aucun accès au service de découverte.

### 11.10 Interface

La vue « Project » porte une section dépliable :

```
Changements Git      2
  Branche            feature/paiement
  Fichiers modifiés  7 fichiers · +142 / −31
  Introduits par ce changement   2
  Préexistants                   5
```

« Préexistants » n'est **jamais** en rouge : ces problèmes sont réels,
mais ce changement ne les a pas causés, et les teinter comme s'il en
était responsable brouillerait la seule distinction qui compte ici.

Quand l'analyse n'a pas conclu, la ligne « Introduits » affiche
« Non vérifié » plutôt qu'un `0` — un zéro resterait lisible comme un feu
vert, même accompagné d'une infobulle que personne n'ouvre.

### 11.11 Réglages

| Réglage | Défaut | Ce qu'il décide |
| --- | --- | --- |
| `wazuhSecurity.git.enabled` | `true` | Analyse des changements Git |
| `wazuhSecurity.git.prePushProtection` | `warn` | `off` / `warn` / `block` |
| `wazuhSecurity.git.maxChangedFiles` | `50` | Seuil du mode réduit |
| `wazuhSecurity.git.budgetMs` | `2500` | Budget d'une vérification |

Une valeur inconnue pour `prePushProtection` retombe sur `warn`, jamais
sur `block` : un réglage mal orthographié ne doit pas durcir la protection
à l'insu de l'utilisateur.

Aucun réglage backend : la phase 4 n'ajoute **aucune route**.

### 11.12 Commandes

| Commande | Effet |
| --- | --- |
| **Scan Git Changes** | Relance l'analyse et affiche le bilan |
| **Check Changes Before Push** | Applique la politique `off` / `warn` / `block` |

### 11.13 Limites connues

- **Un `push` fait depuis un terminal n'est pas intercepté.** C'est la
  contrepartie directe du refus d'installer un hook. La limite est dite à
  l'utilisateur au passage en mode `block`.
- **L'analyse de code ne tourne pas sur le diff.** Seule la recherche de
  secrets est relancée sur les fichiers modifiés ; les findings de code
  viennent du registre, alimenté par la phase 3. Un problème de code
  introduit à l'instant est donc attribué correctement **dès que** la
  surveillance continue l'a fait analyser — pas avant.
- **Un renommage produit deux entrées**, l'ancienne supprimée et la
  nouvelle ajoutée. C'est correct, mais tout ce que porte le fichier
  renommé est alors classé « introduit ».
- **Un seul dépôt est suivi** : celui du premier dossier du workspace.
  Un workspace multi-racines n'est analysé que pour sa première racine.
- **`diffWithHEAD` ne couvre pas les commits non poussés.** L'analyse
  porte sur l'index et l'arbre de travail. Un problème introduit par un
  commit déjà fait mais non poussé est vu comme préexistant.

---

## 12. Sécurité d'API (phase 5)

Les phases précédentes répondent à « que contient ce projet ? » et « qu'ai-je
changé ? ». La phase 5 en pose une troisième : **« qu'est-ce que ce projet
expose, et à qui ? »**

### 12.1 Ce qui est détecté

| Famille | Règles | Confiance |
| --- | --- | --- |
| Endpoint sans authentification | `API-AUTH-001/002/003` | `MEDIUM`, `HIGH` si déclaré public |
| Autorisation manquante | `API-AUTHZ-001` | `MEDIUM` |
| CORS | `API-CORS-001/002/003` | `HIGH` avec identifiants, sinon `MEDIUM` |
| Transport | `API-TLS-001/002` | `HIGH` si vérification désactivée |
| Surfaces de diagnostic | `API-DEBUG-001/002` | `HIGH` / `MEDIUM` |
| Identifiants écrits en dur | `API-CRED-001/002` | `MEDIUM` / `HIGH` |

Frameworks reconnus : **FastAPI**, **Flask**, **Django**, **Express**,
**NestJS**, **Spring**, **Laravel**, **ASP.NET** — ceux que la découverte
de la phase 1 sait déjà nommer.

### 12.2 Pourquoi une analyse par lignes, et pas un AST

Un analyseur syntaxique par langage voudrait dire embarquer un parseur
Python, un parseur TypeScript, un parseur Java et un parseur PHP dans une
extension qui n'a **aucune dépendance**. Le coût est disproportionné : les
déclarations de routes sont, dans tous ces frameworks, des formes locales
et très régulières — un décorateur, ou un appel de méthode.

La conséquence est assumée et documentée : **l'agent ne voit que ce qui
est écrit littéralement.** Une route montée par métaprogrammation, ou dont
le chemin vient d'une variable, ne sera pas vue. C'est pourquoi la vue
écrit « Aucun reconnu » et non « Aucune API ».

### 12.3 Ne pas crier au loup

C'est la contrainte qui a le plus façonné le moteur. Une analyse par
lignes ne voit qu'un fichier : une authentification posée par un
middleware monté ailleurs lui est invisible. Sans garde-fous, un projet
correctement protégé recevrait un signalement **par route** — et l'outil
serait désactivé dans la semaine.

Quatre garde-fous, dans l'ordre où ils s'appliquent :

1. **l'authentification globale fait taire la règle.** Un fichier qui
   monte `app.use(requireAuth)`, déclare
   `FastAPI(dependencies=[Depends(auth)])` ou fixe
   `DEFAULT_PERMISSION_CLASSES` ne produit aucun « endpoint non
   authentifié » ;
2. **seules les routes qui comptent sont signalées.** Une lecture (`GET`)
   sur un chemin banal ne produit rien. Une écriture, ou un chemin
   privilégié, oui ;
3. **la liste des chemins sensibles est courte et défendable.** `users`,
   `orders`, `accounts` en sont **absents** : ce sont des noms de
   ressource ordinaires, et exiger un contrôle de rôle sur chaque
   `/api/users` produirait exactement le bruit à éviter. `/admin/users`
   reste couvert, par `admin` ;
4. **la confiance plafonne la gravité.** Le backend applique
   `apply_confidence` : une détection moyennement sûre ne s'affiche
   **jamais** en `CRITICAL`.

Un fichier de test voit sa confiance abaissée d'un cran : il décrit des
routes, il n'en expose pas.

### 12.4 Aucune seconde architecture de findings

Le moteur produit des `ApiFindingSubmission`, que le backend range en
`SecurityFinding` de catégorie `API` — la même table, la même
réconciliation par empreinte, la même vue, les mêmes diagnostics, les
mêmes règles de dédoublonnage des bulles.

`API` était déclarée dans `SecurityCategory` depuis la phase 2, et
inutilisée. La phase 5 la remplit ; rien n'a été créé à côté.

### 12.5 Séquence

```
POST /api/project/{uid}/api-security     constats  ->  findings + stats
GET  /api/project/{uid}/findings         relecture ->  findings unifiés
```

Une seule route ajoutée, calquée sur `/secrets`. L'empreinte a pour
discriminant **la règle et le type de problème**, jamais la preuve : deux
analyses du même fichier produisent la même empreinte, et une décision
« faux positif » survit à la suivante.

### 12.6 Ce qui traverse la frontière

    TRAVERSE   chemin relatif, ligne, règle, type, méthode, chemin de
               route, framework, et un extrait de **déclaration**
    NE TRAVERSE PAS   le contenu du fichier, le corps d'un gestionnaire

L'extrait est borné à 400 caractères et passe par `redact_evidence` à
l'entrée du backend, comme toute preuve. Une ligne de configuration d'API
est précisément l'endroit où un jeton se glisse
(`Authorization: Bearer …`), et le backend n'accorde aucune confiance à
l'expurgation du client.

### 12.7 Surveillance continue

L'analyse d'API se greffe sur le **même déclencheur** que la détection de
secrets : un fichier texte modifié est lu **une fois**, et les deux
moteurs le regardent. Aucun second passage sur le disque, aucun nouveau
type de travail dans la file.

`SecurityBaseline` conserve les constats d'API par fichier, exactement
comme pour les secrets : un fichier modifié remplace sa seule entrée, et
le lot complet est reconstitué sans relire le projet. Un fichier réanalysé
qui rend les mêmes constats ne déclenche **aucune** soumission.

Le décompte de routes est repris du parcours de référence : le remettre à
zéro parce qu'un seul fichier a changé ferait afficher « aucune route
reconnue » à un projet qui en expose vingt.

### 12.8 Interface

```
Sécurité d'API          3
  Endpoints détectés    12
  Sans authentification  2
```

« Jamais analysé » et « aucun problème » ne s'écrivent pas pareil.
« Endpoints détectés » dit la **couverture**, pas le risque, et son
infobulle le précise.

### 12.9 Réglages

| Réglage | Défaut | Ce qu'il décide |
| --- | --- | --- |
| `wazuhSecurity.project.apiSecurity` | `true` | Analyse d'API, **entièrement locale** |

Côté backend (`backend/.env`) :

| Variable | Défaut | Rôle |
| --- | --- | --- |
| `API_SECURITY_ENABLED` | `true` | Réception des analyses d'API |
| `API_MAX_FINDINGS` | `500` | Plafond serveur, annoncé quand il mord |

Une capacité désactivée répond **503**, jamais une liste vide.

Aucune sortie réseau : l'analyse d'API ne contacte aucun service externe,
et fonctionne avec Wazuh complètement arrêté — un test le vérifie sur le
code source du module.

### 12.10 Limites connues

- **Seul ce qui est écrit littéralement est vu.** Routes montées
  dynamiquement, chemins construits par variable, `include_router` avec
  préfixe : le chemin complet n'est pas reconstitué.
- **Go, Ruby, Rust et PHP hors Laravel ne sont pas couverts.** L'agent se
  tait plutôt que de deviner ; le décompte dit « aucun reconnu ».
- **L'authentification globale n'est vue que dans le même fichier.** Un
  middleware monté dans `main.py` ne fait pas taire les règles de
  `routes/admin.py`. Ces signalements sont à écarter comme faux positifs,
  et leur texte de remédiation le dit explicitement.
- **Chevauchement possible avec la détection de secrets.** Un jeton dans
  un en-tête `Authorization` peut produire un finding `SECRET` **et** un
  finding `API`. Les deux sont exacts et se lisent différemment — l'un
  dit « cette valeur est un secret », l'autre « cet appel d'API porte un
  identifiant en dur » — mais l'utilisateur voit deux lignes.
- **Aucune analyse inter-fichiers.** Un routeur déclaré ici et monté
  ailleurs n'est pas relié.
- **Rien n'est exécuté.** Aucune requête n'est envoyée à l'API analysée :
  l'analyse est statique, et tester une API en la sollicitant serait une
  décision d'une tout autre nature.

---

## 13. Préparation des phases suivantes

Le contexte est conçu pour être étendu, sans couplage à une capacité
particulière :

| Phase | Ce qui est déjà en place |
| --- | --- |
| 2 — secrets, dépendances | **Implémentée.** Voir §9 : détection locale, preuves expurgées, inventaire sans installation, fournisseur OSV derrière une interface |
| 3 — surveillance continue | **Implémentée.** Voir §10 : `content_hash` + `mtime` + `size` alimentent le triple niveau de cache, et la file d'analyses absorbe les rafales |
| 4 — Git | **Implémentée.** Voir §11 : diff via `vscode.git`, attribution introduit/préexistant, protection avant push |
| 5 — API | **Implémentée.** Voir §12 : routes, authentification, autorisation, CORS, transport, surfaces de diagnostic |
| 6 — assistant IA | **Implémentée.** Explique un `SecurityFinding` existant, résume les findings d'un projet, chat de sécurité. Contexte construit par `app/ai/security_context.py` (preuve réexpurgée, chemin relatif, `ai_contract.py` pour le projet) ; explications en cache dans une table séparée ; gravité recopiée du moteur, jamais produite par l'IA ; 503 sans clé API, la détection restant inchangée |
| 7 — remédiation | **Implémentée.** « Suggest Fix with AI » : éligibilité déterministe (jamais `.env`, clé, certificat, identifiants, verrou), extrait borné et expurgé, proposition validée strictement des deux côtés (`app/ai/security_fix.py`, `src/remediation/aiFix.ts`), diff natif, confirmation modale, application bornée avec retour arrière, puis réanalyse déterministe (`ProjectMonitor.rescanFile`) — aucune décision « corrigé » enregistrée par l'IA. Les correctifs déterministes d'une ligne (`fixGuard`, `code_fixes`) restent inchangés |
| 8 — posture, CI/CD | **Implémentée.** Voir §14 : posture explicable par domaine sans score, contrôle CI déterministe off / warn / block, `dist/ci-check.js` hors de VS Code, sans IA ni Wazuh |

Le contrat IA mérite une mention : il est écrit avant l'assistant
précisément parce que la tentation, le jour où l'assistant arrivera, sera
de lui passer « tout le contexte, ce sera plus pratique ». Un type qui ne
peut pas porter un secret rend cette facilité impossible.

---

## 14. Posture de sécurité et CI/CD (phase 8)

La posture **lit** ce que les moteurs déterministes ont déjà établi. Aucun
moteur nouveau, aucune table nouvelle, **aucun score**, aucune IA.

### 14.1 Ce qui est affiché

```
GET /api/project/{uid}/posture
├── analysis      not_analyzed | partial | complete
├── findings      total, critical, high, medium, low (findings ouverts ;
│                 code : dernier scan de chaque fichier seulement — y
│                 compris un scan resservi par le cache ; un fichier absent
│                 d'un index complet postérieur à son scan est écarté)
├── areas[]       secrets, dependencies, code, api, git
│                 state     not_analyzed | unavailable | no_findings | findings
│                 coverage  not_analyzed | complete | partial | unavailable
│                 findings  null = jamais analysé — JAMAIS 0
│                 warnings  ce qui rend l'analyse incomplète
├── coverage      fichiers indexés / découverts, troncature, fichiers
│                 sensibles, langages sans règles, état du fournisseur
└── history       « Historique insuffisant » : les résolutions ne sont
                  pas conservées, aucune tendance n'est inventée
```

Un domaine devient `partial` quand un balayage a été plafonné, que l'index
est tronqué, que des dépendances n'ont pas pu être vérifiées, que le
fournisseur de vulnérabilités n'a pas conclu (s'il y avait quelque chose à
vérifier), ou que des fichiers source n'ont pas été analysés. Le domaine
Git est `unavailable` côté backend : l'attribution de la phase 4 est locale,
et la vue Project la complète avec son propre bilan.

La vue **Project** affiche la section juste sous l'état du projet :
posture, gravités, couverture, domaines, surveillance, et le statut CI/CD
pour la politique `wazuhSecurity.ci.policy`.

### 14.2 Contrôle CI/CD

```
POST /api/project/{uid}/ci-check     { mode?, fail_on?, warn_on? }
```

| Mode | Effet |
| --- | --- |
| `off` | Conditions mesurées, rien signalé, sortie 0 |
| `warn` | **Défaut.** Conditions signalées, jamais de blocage |
| `block` | Les conditions de `fail_on` bloquent (sortie 1), celles de `warn_on` avertissent |

Conditions : `critical_findings`, `high_findings`, `secrets_present`,
`vulnerable_dependencies` (bloquantes par défaut), `analysis_incomplete`,
`vulnerability_provider_unavailable`, `unsupported_languages`
(avertissements par défaut). Configurables par `CI_POLICY_MODE`,
`CI_FAIL_ON`, `CI_WARN_ON`, ou par requête. Un mode inconnu retombe sur
`warn`. Un blocage porte toujours ses `reasons`.

Le résultat (`schema_version: "1.0"`) ne porte ni preuve, ni secret, ni
chemin absolu, ni empreinte de la racine : identifiant de projet, nom du
dossier, compteurs, conditions, raisons, findings CRITICAL/HIGH avec chemin
relatif validé et titre réexpurgé.

### 14.3 Hors de VS Code

`node dist/ci-check.js` enchaîne les pièces de l'extension —
découverte, secrets, API, dépendances, analyse de code par la route
existante — puis demande le verdict au backend :

```
uvicorn app.main:app --port 8000 &          # sans OPENAI_API_KEY, sans Wazuh
WAZUH_SECURITY_TOKEN=… node dist/ci-check.js --root . --policy block --output security.json
```

| Sortie | Sens |
| --- | --- |
| `0` | conforme, avertissement, ou contrôle désactivé |
| `1` | bloqué par la politique |
| `2` | contrôle impossible **en mode `block`** (en `warn`/`off`, une panne sort en 0 avec `status: "error"`) |
| `64` | arguments invalides |

Rapport JSON sur la sortie standard, journal sur la sortie d'erreur. Aucun
fichier sensible n'est lu ; l'analyse de code est plafonnée
(`--max-code-files`, 300) et le plafond est annoncé.

### 14.4 Limites connues

- **Pas d'historique.** Les findings résolus sont supprimés par la
  réconciliation ; aucune tendance n'est reconstituée.
- **Le backend doit tourner pendant le contrôle CI** : il détient la
  persistance, les règles de code et la base de vulnérabilités.
- **Cache de l'analyse de code.** Un fichier au contenu identique, au même
  chemin relatif, déjà analysé pour un autre projet est resservi depuis le
  cache et reste rattaché à ce projet : le domaine « code » du second est
  sous-compté, et annoncé `partial` (fichiers analysés < fichiers
  couverts). Aucune donnée du premier n'est révélée — le contenu est
  identique — mais le finding est **le même enregistrement** : une décision
  (« Dismiss ») prise depuis le second s'applique aussi au premier.
- **Git reste local à l'éditeur** : le contrôle CI ne l'évalue pas.

