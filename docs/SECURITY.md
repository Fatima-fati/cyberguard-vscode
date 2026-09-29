# Modèle de sécurité de l'agent

Ce document décrit ce qui protège l'agent lui-même, et ce qui ne le protège
pas encore. Il porte sur les phases **0** et **1** ; les phases suivantes
(détection de secrets, dépendances, Git, API, assistant IA) ne sont pas
implémentées et sont signalées comme telles.

Principe directeur, appliqué partout dans ce document :

> **Collecter le minimum d'informations nécessaire à l'analyse de
> sécurité.** La métadonnée est persistée, le contenu est transitoire.

---

## 1. Le paradoxe de l'agent de sécurité

Un agent de sécurité lit beaucoup et parle beaucoup. Sa surface d'attaque
croît à chaque capacité ajoutée. Trois règles tiennent cette croissance :

1. **Inventaire fermé des sorties réseau.** Aujourd'hui : le backend local,
   et OpenAI *si et seulement si* l'enrichissement est explicitement activé.
   Rien d'autre. Toute nouvelle destination est une décision consciente,
   pas un effet de bord.
2. **Principe du moindre contenu.** Chaque octet qui quitte le poste doit
   être justifié. Le contexte de projet est fait de métadonnées
   précisément pour cela.
3. **Auto-analyse.** L'agent doit pouvoir s'appliquer ses propres règles.
   Ce projet n'a pas détecté sa propre clé OpenAI dans `backend/.env` —
   parce qu'il ne scanne pas les `.env`. C'est le meilleur argument pour la
   phase 2.

---

## 2. Authentification locale

### Le problème

Le backend écoute sur la machine du développeur et expose des routes qui
déclenchent des analyses, lisent des findings et diffusent des extraits de
code. Sans contrôle, **tout processus local** peut les appeler — y compris
pour consommer une clé OpenAI facturée.

### Le mécanisme

```
Extension                            Backend
    │                                   │
    │  lit ~/.wazuh-security/           │  génère le jeton au démarrage
    │      agent-token      ◄───────────│  (secrets.token_urlsafe, 256 bits)
    │  conserve dans SecretStorage      │
    │                                   │
    │  Authorization: Bearer <jeton>    │
    │──────────────────────────────────►│  secrets.compare_digest
    │                                   │
    │◄──── 200 ─────────────────────────│  valide
    │◄──── 401 + WWW-Authenticate ──────│  absent, malformé ou faux
```

### Propriétés tenues

| Propriété | Comment |
| --- | --- |
| Jamais en dur | Généré au démarrage, jamais dans le code ni dans le manifeste |
| Jamais commité | Rangé dans le profil utilisateur, hors du dépôt ; `.gitignore` couvre le cas d'un `AGENT_TOKEN_PATH` mal placé |
| Jamais journalisé | Les refus tracent le chemin appelé et la *forme* du problème, jamais la valeur |
| Jamais dans un message d'erreur | Le 401 dit « absent » ou « invalide », rien de plus |
| Jamais envoyé à un service externe | Seul le backend local le connaît |
| Comparaison à temps constant | `secrets.compare_digest` : la durée ne révèle pas le préfixe correct |
| Stockage côté extension | `SecretStorage` (trousseau du système), jamais `settings.json`, `globalState` ni le code source |

### Périmètre

| Route | Authentification | Pourquoi |
| --- | --- | --- |
| `GET /api/code/health` | **Publique** | Route de diagnostic. Si elle exigeait un jeton, un problème d'authentification serait indiscernable d'un backend éteint — et le seul symptôme serait une extension muette. Elle annonce `auth_required` pour que le reste soit interprétable. |
| `GET /api/code/rules` | Requise | |
| `POST /api/code/scan` | Requise | Reçoit le contenu des fichiers |
| `GET /api/code/scans/{uid}` | Requise | |
| `GET /api/code/findings` | Requise | |
| `POST /api/code/findings/{uid}/fix` | Requise | |
| `POST /api/code/findings/{uid}/decision` | Requise | |
| `GET /api/code/stats` | Requise | |
| `GET /api/stream` | Requise | Diffuse des extraits de code |
| `POST /api/project/discover` | Requise | |
| `POST /api/project/{uid}/index` | Requise | |
| `GET /api/project/{uid}/context` | Requise | Décrit l'arborescence du projet et ses fichiers sensibles |

L'implémentation place les routes protégées sur un **sous-routeur portant
la dépendance d'authentification**. Le défaut est donc « protégé » : une
route ajoutée demain l'est sans qu'on y pense.

### Reprise automatique

Le backend peut redémarrer et régénérer son jeton. L'extension détient
alors une valeur périmée. Sur un 401, elle **relit le fichier une seule
fois** et réessaie. Sans cette reprise, elle resterait muette jusqu'au
redémarrage de l'éditeur ; avec plus d'une tentative, elle accumulerait des
refus dans les journaux du backend.

### Limite connue

Un processus local tournant sous le **même compte utilisateur** peut lire
le fichier de jeton et se faire passer pour l'extension. C'est une limite
inhérente au modèle : sur un poste mono-utilisateur, aucun secret local ne
protège contre un processus de ce même utilisateur. Le dispositif ferme les
appels *anonymes* — ce qui est l'exposition réelle — pas une compromission
du compte.

---

## 3. Mode d'écoute : local contre distant

| | Développement local | Déploiement distant |
| --- | --- | --- |
| `API_HOST` | `127.0.0.1` (**défaut**) | `0.0.0.0` |
| Joignable depuis | Cette machine uniquement | Le réseau |
| `AGENT_AUTH_ENABLED` | `true` | `true`, sans exception |
| `CORS_ORIGINS` | Valeur de développement | Restreint aux origines réellement attendues |
| TLS | Sans objet | Obligatoire, via un reverse proxy |

Le défaut est la boucle locale : le backend détient des identifiants et
diffuse des extraits de code, l'exposer au réseau doit être une décision.
Le démarrage **annonce le mode retenu** dans les journaux — un backend
joignable depuis le réseau ne doit pas se découvrir après coup.

Commande de développement recommandée :

```bash
cd backend
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

---

## 4. Adresse du backend : le chemin d'exfiltration

`wazuhSecurity.backendUrl` décide où part le **contenu intégral** de chaque
fichier analysé. C'est le seul chemin d'exfiltration du code de
l'utilisateur, et il était exploitable par un dépôt cloné :

```
1. le développeur clone un dépôt tiers
2. .vscode/settings.json y contient
     "wazuhSecurity.backendUrl": "https://attaquant.example"
3. le développeur fait confiance au workspace (geste réflexe)
4. à chaque sauvegarde, le fichier entier part chez l'attaquant
```

L'extension se comporterait exactement comme prévu. **Trois défenses
indépendantes**, parce que les deux premières dépendent du manifeste et la
troisième vaut quel que soit le chemin par lequel l'adresse arrive :

1. **`"scope": "machine"`** sur `backendUrl` et `allowRemoteBackend` — le
   réglage n'est plus modifiable par le `.vscode/settings.json` d'un dépôt.
2. **`capabilities.untrustedWorkspaces`** avec
   `restrictedConfigurations: ["wazuhSecurity.backendUrl",
   "wazuhSecurity.allowRemoteBackend"]` — VS Code ignore explicitement ces
   réglages dans un workspace non fiable, et l'utilisateur voit pourquoi.
3. **Validation à l'usage** (`src/api/backendUrl.ts`) :

| Cas | Comportement |
| --- | --- |
| `http://127.0.0.1:8000` | Accepté |
| `http://localhost`, `http://[::1]`, `127.0.0.0/8` | Accepté |
| Protocole autre que `http`/`https` | **Refusé** |
| Identifiants dans l'URL (`http://u:p@hôte`) | **Refusé** — ils partiraient dans chaque requête |
| Chemin, requête ou fragment | **Refusé** — le backend est une origine, pas une page |
| URL malformée, hôte absent | **Refusé** |
| Hôte distant | **Refusé**, sauf `wazuhSecurity.allowRemoteBackend` explicite |
| `0.0.0.0` | Traité comme **distant** — c'est une adresse d'écoute, pas de destination |

Une adresse refusée n'est **pas corrigée en silence** : l'extension affiche
la raison, annonce le repli sur la boucle locale — l'option la plus
restrictive — et marque la barre d'état. Un backend distant autorisé reste
signalé **en permanence** dans la barre d'état : c'est l'indice qui permet
de s'apercevoir que le code part ailleurs.

Aucune résolution DNS n'est tentée : un nom qui résout aujourd'hui vers
`127.0.0.1` peut résoudre demain ailleurs, et une validation dépendante du
réseau ne serait pas fiable.

---

## 5. Cloisonnement du flux temps réel

Un événement `code_finding` porte un **extrait du code analysé**. Le flux
était un broadcast global : n'importe quel abonné recevait les extraits de
tous les projets.

```
publish(event)                     → tous les abonnés
                                     (alertes Wazuh : portée globale)

publish(event, project_uid="abc")  → uniquement les abonnés
                                     inscrits sur « abc »
```

La règle est **volontairement dissymétrique** : un abonné qui ne déclare
pas de projet ne reçoit **aucun** événement de projet. Si l'omission
donnait accès à tout, le cloisonnement serait déclaratif, donc inexistant.

Garantie vérifiée par les tests : *un finding du projet A n'atteint jamais
un client abonné au projet B.* L'extension se défendait déjà côté client
(`upsertIfTracked` refuse ce qu'elle n'a pas analysé), mais une défense
côté client protège le client, pas les autres.

Les alertes Wazuh n'appartiennent à aucun projet et conservent une portée
globale : le cloisonnement ne casse pas la supervision existante.

---

## 6. Ce que le contexte de projet contient — et ne contient pas

### Collecté

| Information | Source |
| --- | --- |
| Empreinte du chemin racine (`root_hash`) | SHA-256 local |
| Nom du projet | Dernier segment du chemin |
| Langages et proportions | Extensions de fichiers |
| Frameworks, avec leur preuve | Noms de dépendances déclarées, fichiers de configuration |
| Types de projet | Déduits des deux précédents |
| Index : chemin relatif, taille, empreinte, date | Parcours local |
| Manifestes, configuration, infrastructure | Motifs de noms |
| Fichiers sensibles : chemin, type, raison | Motifs de noms |
| Présence d'un dépôt Git, hôte du remote | API `vscode.git` |

### Collecté depuis la phase 2 — des nombres, jamais des valeurs

| Champ | Contenu |
| --- | --- |
| `secret_statistics` | Décomptes par gravité, nombre de fichiers concernés, volume analysé |
| `dependency_statistics` | Total, directes, transitives, vulnérables, **non vérifiées** |
| `dependency_ecosystems` | Volumes par écosystème, dont la part réellement vérifiée |
| `vulnerability_statistics` | Décomptes, **état du fournisseur**, message rédigé |

Aucun de ces champs ne peut porter la valeur d'un secret : leurs types ne
contiennent que des entiers, des libellés d'écosystème et un état de
fournisseur. Le détail — quel fichier, quelle ligne, quelle preuve
expurgée — vit dans les findings (`GET /api/project/{uid}/findings`), pas
dans le contexte : un résumé qui grossit à chaque balayage cesse d'en être
un.

`vulnerability_statistics` porte `provider_status` et `conclusive`. Sans
eux, un `total: 0` se lirait comme un feu vert alors qu'il peut signifier
« la base n'a pas répondu ».

### Jamais collecté

| Information | Pourquoi |
| --- | --- |
| Chemin absolu du workspace | Révèle le nom de l'utilisateur et l'arborescence du poste. Seul `root_hash` circule. |
| Contenu d'un fichier | Transitoire par construction : lu le temps d'une requête d'analyse, jamais persisté. |
| Contenu d'un fichier sensible | **Jamais lu, pas même pour calculer une empreinte** : « lire pour hacher » reste lire. |
| Versions de dépendances | La ligne qui les porte peut contenir des identifiants (`--index-url https://u:p@dépôt/`). Seuls les **noms** sont extraits. |
| URL complète d'un remote Git | Peut porter un jeton d'accès. Seul l'hôte est conservé. |
| Historique Git | Hors périmètre de cette phase. |
| Score de sécurité | La posture explicable, avec sa couverture, appartient à la phase 8. Un chiffre sans son explication serait pris pour un verdict. |

`workspacePath` figure dans le modèle **côté extension uniquement**
(`LocalProjectView`) : il sert à l'infobulle et aux messages destinés à
l'utilisateur, qui connaît déjà son disque. Il ne franchit jamais la
frontière HTTP.

### Fichiers sensibles : indexés, jamais lus

Un `.env` **apparaît** dans l'index — sa présence est précisément ce que la
découverte doit constater — mais il n'est jamais ouvert. Il est donc
enregistré sans empreinte, avec son type et la raison de son classement :

```
.env
  type   : environment-secrets
  reason : peut contenir des identifiants
```

Les modèles (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`)
ne sont **pas** classés sensibles : leur raison d'être est de ne porter
aucune valeur, et les inclure banaliserait la liste — une liste banalisée
n'est plus lue.

**Limite du classement par nom :** il porte sur le **nom**, seule
information disponible sans ouvrir le fichier. Un `config.local.js`
contenant une clé privée n'apparaîtrait pas ici.

C'est ce que la **détection de secrets par contenu** (phase 2, §11) vient
compléter : elle lit les fichiers qui *ne sont pas* classés sensibles, y
cherche des motifs de clés, et ne transmet qu'une preuve expurgée. Les
fichiers classés sensibles, eux, restent non lus — la règle ci-dessus n'est
pas relâchée.

---

## 7. Bornes de la découverte

Aucune borne n'est atteinte en silence : chaque plafond produit un
avertissement remonté à l'utilisateur et affiché dans la vue.

| Borne | Valeur | Raison |
| --- | --- | --- |
| Fichiers indexés | 20 000 | Un monorepo ne doit pas bloquer l'ouverture |
| Profondeur | 24 niveaux | Seconde ceinture contre une boucle de liens |
| Taille pour hachage | 2 Mo | Taille et date suffisent à détecter un changement |
| Taille d'un manifeste | 512 Ko | Au-delà, ce n'est plus un manifeste |
| Noms de dépendances | 500 par manifeste | Borne la taille de la requête |

**Jamais parcouru :** `node_modules`, `.git`, `.venv`, `venv`, `env`,
`__pycache__`, `dist`, `build`, `out`, `out-test`, `target`, `bin`, `obj`,
`vendor`, `coverage`, `logs`, `tmp`, `temp`, `.next`, `.nuxt`,
`.svelte-kit`, `.turbo`, `.gradle`, `Pods`, `.terraform`, `.mypy_cache`,
`.pytest_cache`, `.ruff_cache`, `.tox`, `bower_components`, `.pnpm-store`,
`.yarn`, `.cache`, `.parcel-cache`, `.idea`, `.vs`, `site-packages`,
`virtualenv`.

**Liens symboliques : jamais suivis.** Un lien peut pointer hors du
workspace, y compris vers un dossier système. Le nombre de liens écartés
est annoncé.

**Jamais lu** (mais indexé) : fichiers sensibles, binaires, médias,
archives, bases de données, artefacts de build.

Le `.gitignore` du projet est respecté, avec le *fail-open* du lecteur
existant : un motif mal compris laisse le fichier **indexé**, jamais écarté
à tort — un fichier manqué crée un angle mort de sécurité, un fichier
indexé en trop coûte une ligne dans un décompte.

### Performance

La découverte est **asynchrone**, **annulable** (croix de la barre de
progression, ou désactivation de l'extension), **bornée** et **non
bloquante** : `withProgress` sur la barre d'état, jamais de modale.
L'éditeur reste utilisable pendant le parcours, et l'analyse d'un fichier
fonctionne sans contexte de projet.

Une seule découverte à la fois : un second appel est **refusé**, pas mis en
file — deux parcours concurrents doubleraient le coût pour un résultat
identique.

---

## 8. Surfaces de l'extension

| Surface | État | Détail |
| --- | --- | --- |
| Secrets dans l'extension | ✅ | Aucun. Le jeton vient du backend et vit dans `SecretStorage`. |
| Clé API | ✅ | Backend uniquement, jamais renvoyée, jamais journalisée. |
| `backendUrl` | ✅ | `scope: machine` + `capabilities` + validation (§4). |
| Confiance en localhost | ✅ | Authentification requise (§2). |
| Injection de commande | ✅ | Aucun `child_process`, `exec`, `spawn` ni `eval` dans l'extension. Git passe par l'API `vscode.git`. |
| Traversée de chemin | ✅ | `toRelativePath` refuse `..` ; l'index ne porte que des chemins relatifs, et le backend **revalide** (chemin absolu, `..`, lettre de lecteur → 422). |
| Écriture de fichier | ✅ | L'extension n'écrit aucun fichier. Les corrections passent par `WorkspaceEdit`, après modale, annulables par Ctrl+Z. |
| Workspace non fiable | ✅ | `capabilities.untrustedWorkspaces: "limited"` déclaré, avec la liste des réglages restreints. |
| Workspace virtuel | ✅ | Déclaré non pris en charge : l'analyse lit le disque. |
| Sécurité WebView | ✅ | CSP `default-src 'none'`, nonce régénéré par rendu, `localResourceRoots: []`, `enableCommandUris: false`. La vue Project est une `TreeView` : aucun HTML. |
| XSS | ✅ | `escapeHtml` dans la fiche ; les `TreeItem` sont affichés en texte brut par VS Code. |
| Exfiltration de données | ✅ | Fermée par §4. |
| Journaux | ✅ | Forme uniquement — méthode, URL, code HTTP, durée, identifiants, volumes. Jamais de corps, jamais de jeton, jamais un chemin de fichier sensible, jamais le chemin absolu du workspace. |
| Télémétrie | ✅ | Aucune. |
| Dépendances runtime | ✅ | **Zéro.** Inchangé par ces deux phases. |
| Prompt injection | ✅ | Phase 6 : règle de défense explicite dans les trois consignes système (`app/ai/security_prompts.py`), et surtout impossibilité structurelle — les sorties de modèle ne portent ni gravité, ni statut, ni identifiant, et l'assistant n'écrit jamais dans `security_findings` (vérifié par test sur l'AST du code). |
| Détection de secrets par contenu | ❌ | Phase 2. Le classement actuel est nominal (§6). |

---

## 9. Journalisation

Les identifiants remplacent les valeurs, partout :

| À la place de | On journalise |
| --- | --- |
| Chemin absolu du workspace | `projectId` (12 premiers caractères de `root_hash`) |
| Contenu d'un fichier | Taille et empreinte tronquée |
| Jeton | Rien ; l'origine (`secretStorage`, `tokenFile`) et le chemin appelé |
| Corps de requête ou de réponse | Méthode, URL, code HTTP, durée |
| Chemin d'un fichier sensible | Le **nombre** de fichiers sensibles |
| Valeur d'un secret | Jamais, à aucune étape — y compris dans les journaux du moteur de détection |
| Preuve d'un secret | Le **type** et le **nombre**, jamais la preuve elle-même |
| Dépendances du projet | Volumes par écosystème ; les noms ne sont journalisés nulle part |
| Erreur système | Le code (`ENOENT`, `EACCES`), pas la trace d'exécution |

Aucune trace d'exécution n'atteint l'utilisateur : le détail technique
reste dans le canal de sortie « Wazuh Security », le message affiché dit
quoi faire.

---

## 10. Gestion des `.env`

- **`backend/.env` est local**, jamais versionné, jamais partagé.
- **`backend/.env.example` est le seul fichier de configuration
  partageable.** Toutes ses valeurs sensibles sont vides. Ne jamais y
  écrire une valeur réelle.
- **`.gitignore` ne protège que ce qui n'est pas déjà suivi.** Un fichier
  ajouté à l'index avant l'ajout d'une règle y reste. Avant le premier
  commit :

  ```bash
  git ls-files | grep -Ei "\.env|\.pem|\.key|agent-token"
  ```

- **Une clé exposée est compromise.** La retirer du fichier ne suffit pas :
  il faut la révoquer chez le fournisseur et en générer une nouvelle.

---

## 11. Détection de secrets : où elle tourne, et ce qui en sort

### Le choix structurant

La détection tourne **sur le poste, dans l'extension**. Ce n'est pas une
optimisation :

> Lire un fichier du développeur pour y chercher un secret est une
> opération locale. Envoyer ce fichier à un serveur pour la même raison
> n'en serait pas une.

Le backend ne lit jamais le disque du développeur. Il reçoit des
**constats** — où, quel type, avec quelle confiance — et une preuve déjà
expurgée.

### Ce qui traverse la frontière HTTP

| Champ                | Exemple                                     |
| -------------------- | ------------------------------------------- |
| `file_path`          | `backend/config.py` (relatif, jamais absolu) |
| `line`, `column`     | `24`, `12`                                   |
| `secret_type`        | `openai_api_key`                             |
| `severity`           | `CRITICAL`                                   |
| `confidence`         | `HIGH`                                       |
| `evidence_redacted`  | `OpenAI API key detected: sk-proj-********`  |

Ce qui ne traverse **jamais** : la valeur détectée, la ligne complète, le
contenu du fichier, le chemin absolu.

### Expurgation : deux fois, et la redondance est voulue

```
extension ──► expurgation locale ──► HTTP ──► ré-expurgation ──► SQLite
              protège le poste                protège la base
```

**Côté extension** (`src/security/redaction.ts`). La valeur ne quitte pas
la portée de la fonction qui l'examine : elle est pesée, puis remplacée par
son masque. Expurger plus tard — au moment de l'envoi, par exemple —
laisserait la valeur circuler entre les deux, et une trace de diagnostic
mal placée suffirait à la faire atterrir dans le canal de sortie.

Bornes appliquées, qu'aucun appelant ne peut relâcher :

- jamais plus de **8 caractères** de tête révélés ;
- jamais plus du **quart** de la valeur ;
- **rien** n'est révélé d'une valeur de moins de 12 caractères — montrer
  quatre caractères d'un secret de huit réduirait sérieusement l'espace de
  recherche.

**Côté backend** (`app/security/redaction.py`). Le validateur du modèle
ré-expurge, sans demander la permission. Ce n'est pas de la méfiance
gratuite : le backend écoute en local, et tout processus de la machine peut
poster sur ses routes. Une extension d'une version antérieure, une
extension modifiée ou un `curl` produiraient une preuve en clair. **La
seule garantie qui tienne est celle appliquée du côté qui écrit.**

La seconde passe est générique : tout jeton assez long est masqué, qu'il
corresponde ou non à un fournisseur connu. Une clé d'un service absent du
catalogue est donc protégée elle aussi.

### Vérification

`backend/tests/test_security_secrets.py` poste délibérément une valeur en
clair, puis **relit le fichier SQLite** cellule par cellule. La garantie ne
porte donc pas sur ce que l'API répond, mais sur ce qui est réellement
écrit. Un second test vérifie que la valeur n'apparaît dans aucune ligne de
journal, niveau `DEBUG` compris.

Côté extension, un test construit un fichier contenant **toutes** les
formes reconnues et vérifie qu'aucune ne survit dans aucun finding : si un
seul motif laissait passer sa valeur, il tombe.

### Fichiers sensibles : la règle de la phase 1 est maintenue

`.env`, `.pem`, `id_rsa`, `.npmrc`, `credentials` ne sont **toujours pas
lus** — ni pour les indexer, ni pour les analyser. La phase 2 ne relâche
rien.

Le raisonnement : ces fichiers sont déjà signalés par leur chemin, et leur
raison d'être est de contenir des secrets. Les ouvrir n'apprendrait rien.
La valeur de la détection est ailleurs — trouver un secret **là où il ne
devrait pas être** : code source, configuration versionnée, workflows
d'intégration continue, fichiers de déploiement.

Limite assumée, et elle est réelle : un secret présent uniquement dans un
`.env` non versionné ne produit aucun finding de contenu. Il reste signalé
comme fichier sensible.

---

## 12. Sortie réseau de l'analyse de vulnérabilités

C'est la **seule** sortie réseau des trois moteurs de la phase 2, et elle
est réglable.

### Ce qui sort, exactement

```json
{"queries": [{"version": "4.17.1",
              "package": {"name": "express", "ecosystem": "npm"}}]}
```

Un nom de paquet, son écosystème, sa version. Ni chemin, ni identifiant de
projet, ni contenu, ni nom de dépôt. C'est ce qu'un registre public connaît
déjà de ces paquets.

Un test compare le **corps de requête entier** à cette forme, pas seulement
quelques champs : un champ ajouté par inadvertance fait échouer le build.

### Qui appelle

Le **backend**, jamais l'extension. Un seul composant détient les sorties
réseau vers des tiers, comme pour OpenAI. L'extension demande
(`check_vulnerabilities: true`), le backend décide.

### Comment couper

```bash
# backend/.env
DEPENDENCY_VULNERABILITY_ENABLED=false
```

ou, côté extension, `wazuhSecurity.project.vulnerabilityCheck: false`.

L'inventaire continue de fonctionner. L'interface affiche alors
« vérification désactivée » — **jamais** « aucune vulnérabilité ».

### Disponibilité du fournisseur : la règle d'honnêteté

> « Le fournisseur n'a pas répondu » **n'est pas** « il n'y a pas de
> vulnérabilité ».

L'interface `VulnerabilityProvider` impose de renvoyer un **état**, pas
seulement une liste. Il n'existe aucune forme de retour qui ressemble à
« aucune vulnérabilité » quand la requête a échoué :

| État           | Cause                        | Conclusion possible ? |
| -------------- | ---------------------------- | --------------------- |
| `available`    | la base a répondu            | **oui**               |
| `partial`      | lot plafonné, avis non décrit | **oui**, partiellement |
| `disabled`     | vérification coupée          | non                   |
| `unavailable`  | réseau coupé, DNS muet       | non                   |
| `timeout`      | délai dépassé                | non                   |
| `rate_limited` | quota atteint (429, 403)     | non                   |
| `error`        | 5xx, corps illisible         | non                   |

Chaque état porte une phrase rédigée une seule fois, dans
`app/i18n.PROVIDER_STATUS_MESSAGES`. Aucun chemin de code — backend ou
extension — ne compose sa propre formulation, ce qui est exactement ce qui
garantit qu'aucun ne peut écrire « aucune vulnérabilité » à partir d'un
silence. Le repli, pour un état inconnu d'une version future, est
**pessimiste** : « impossible de vérifier ».

Une dépendance non vérifiée — version non figée, écosystème non couvert,
fournisseur muet — alimente le compteur `unverified` et n'est jamais
comptée comme saine. La base elle-même garde la distinction : la colonne
`verified` de `project_dependencies` est écrite depuis la réponse du
fournisseur, jamais déduite de l'absence de vulnérabilité.

---

## 13. Ce que l'inventaire des dépendances ne fait pas

**Aucune installation, aucune exécution.** Ni `npm install`, ni
`pip download`, ni `mvn dependency:tree`, ni `bundle install`.

Résoudre un arbre de dépendances en lançant le gestionnaire de paquets
reviendrait à **exécuter du code arbitraire venu d'un dépôt qu'on est
précisément en train d'auditer** : un script `postinstall` suffit. C'est la
surface d'attaque la plus évidente d'un outil d'analyse de dépendances, et
elle est fermée par construction — le module ne reçoit que du texte et n'a
aucun moyen de lancer un processus.

Contrepartie assumée : sans fichier de verrouillage, les versions
transitives restent inconnues. Le contexte le dit (`unverified`) plutôt que
de présenter une couverture qu'il n'a pas.

Les lignes d'option des manifestes sont écartées avant toute lecture —
c'est là que se trouveraient d'éventuels identifiants de dépôt privé :

```
--index-url https://utilisateur:motdepasse@depot.example/simple
```

Un nom de paquet ne contient jamais de blanc : ce seul critère écarte ces
lignes par construction, du côté extension comme du côté backend. Un test
vérifie qu'aucun fragment d'une telle ligne n'atteint l'inventaire.

---

## 14. Ce qui n'est pas implémenté

Ces capacités **n'existent pas**. Ce document ne les décrit pas comme
existantes, et l'interface ne les annonce pas.

| Capacité | Phase |
| --- | --- |
| Analyse dédiée des fichiers de configuration (`CONFIGURATION`) | 3 |
| AST / analyse de flux de données | 3 |
| Surveillance continue, file d'attente priorisée | 3 |
| Décision utilisateur sur un finding de sécurité projet (ignorer / corrigé) | 3 |
| Analyse Git (diff, commit), pre-commit, pre-push (`GIT`) | 4 |
| Analyse de sécurité des API (`API`) | 5 |
| Assistant IA conversationnel, raisonnement LLM sur les findings | 6 |
| Remédiation automatique au-delà des 5 réécritures existantes | 7 |
| Posture de sécurité explicable, score, SARIF, CI/CD | 8 |
| Intégration Wazuh (SIEM, infrastructure) comme source **externe** | ultérieure |

Les catégories `CONFIGURATION`, `API` et `GIT` sont **déclarées** dans le
modèle de findings mais produites par aucun moteur. Les nommer fige la
place qu'elles occuperont ; une catégorie annoncée et vide est honnête,
une catégorie inventée après coup casse les filtres déjà écrits.

La contrainte de la phase 1 sur la clé d'unicité du cache
(`UNIQUE (file_path, content_hash)`, sans `project_uid`) est documentée
dans le rapport d'implémentation : le **filtrage** des findings par projet
est en place, la clé de cache elle-même est inchangée.
