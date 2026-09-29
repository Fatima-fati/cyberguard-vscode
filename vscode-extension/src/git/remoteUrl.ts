/**
 * Métadonnées de remote, expurgées.
 *
 * Le problème, en une ligne : **une URL de remote est un endroit où les
 * jetons d'accès se cachent.** `https://x-access-token:ghp_xxx@github.com/org/repo`
 * est une forme parfaitement ordinaire, produite par les intégrations CI
 * et par plusieurs gestionnaires d'identifiants. Elle apparaît dans
 * `git remote -v`, donc dans l'API `vscode.git`, donc à portée de tout
 * code qui journalise « l'URL du dépôt ».
 *
 * Ce module existe pour qu'aucun autre n'ait à y penser : rien d'autre
 * dans la phase 4 ne manipule une URL brute. Deux sorties seulement, et
 * ni l'une ni l'autre ne peut porter d'identifiant :
 *
 *     remoteHostOf()       l'hôte seul, ou `null` au moindre doute
 *     sanitizeRemoteUrl()  une forme affichable, sans userinfo
 *
 * La règle de conduite en cas de doute est toujours la même : **renvoyer
 * moins**. Une URL qu'on ne sait pas lire est réduite à `null`, jamais
 * transmise telle quelle en espérant qu'elle soit inoffensive.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

/**
 * Hôte d'une URL de remote. `null` dès qu'un doute subsiste.
 *
 * Git accepte des formes variées — `https://…`, `git@hôte:org/dépôt`,
 * `ssh://…` — et certaines peuvent porter des identifiants. On n'extrait
 * qu'un nom d'hôte reconnaissable, et on renvoie `null` plutôt que de
 * transmettre une chaîne dont on n'est pas sûr.
 *
 * Déplacé ici depuis `extension.ts` à la phase 4 : c'est de
 * l'expurgation de métadonnée Git, et cela appartient au module Git.
 * Le comportement est inchangé.
 */
export function remoteHostOf(url: string | undefined | null): string | null {
  if (!url) {
    return null
  }

  const trimmed = url.trim()

  // Forme SCP : `git@github.com:org/depot.git`. `new URL()` la refuse.
  const scp = /^[A-Za-z0-9._-]+@([A-Za-z0-9.-]+):/.exec(trimmed)
  if (scp?.[1]) {
    return scp[1].toLowerCase()
  }

  try {
    // `hostname` exclut le port et, surtout, les identifiants éventuels.
    return new URL(trimmed).hostname.toLowerCase() || null
  } catch {
    return null
  }
}

/**
 * Forme affichable d'une URL de remote, **sans identifiants**.
 *
 * Conserve ce qui aide à reconnaître le dépôt — hôte et chemin — et
 * supprime tout le reste. Le `userinfo` (`utilisateur:motdepasse@`) est
 * retiré, y compris quand il ne contient qu'un nom d'utilisateur : rien
 * ne distingue de façon fiable `git@` d'un jeton, et se tromper d'un côté
 * coûte l'affichage d'un identifiant.
 *
 * Renvoie `null` quand l'URL n'est pas interprétable : une chaîne qu'on
 * n'a pas su analyser est précisément celle qu'il ne faut pas afficher.
 */
export function sanitizeRemoteUrl(url: string | undefined | null): string | null {
  if (!url) {
    return null
  }

  const trimmed = url.trim()

  // Forme SCP : `git@github.com:org/depot.git` → `github.com/org/depot.git`.
  const scp = /^[A-Za-z0-9._-]+@([A-Za-z0-9.-]+):(.*)$/.exec(trimmed)
  if (scp?.[1]) {
    const path = (scp[2] ?? '').replace(/^\/+/, '')
    return path ? `${scp[1].toLowerCase()}/${path}` : scp[1].toLowerCase()
  }

  try {
    const parsed = new URL(trimmed)
    // Ce sont ces deux champs qui portent un jeton quand il y en a un.
    parsed.username = ''
    parsed.password = ''
    // `search` et `hash` n'ont rien à faire dans une URL de dépôt, et un
    // `?token=…` y tiendrait parfaitement.
    parsed.search = ''
    parsed.hash = ''

    const host = parsed.hostname.toLowerCase()
    if (!host) {
      return null
    }

    const port = parsed.port ? `:${parsed.port}` : ''
    const path = parsed.pathname.replace(/^\/+/, '')
    return path ? `${host}${port}/${path}` : `${host}${port}`
  } catch {
    return null
  }
}

/**
 * L'URL porte-t-elle des identifiants ?
 *
 * Sert au journal : constater qu'un remote en contient est une
 * information de sécurité utile, alors que la valeur ne l'est jamais.
 * L'appelant écrit « remote avec identifiants intégrés », et rien de plus.
 */
export function carriesCredentials(url: string | undefined | null): boolean {
  if (!url) {
    return false
  }

  const trimmed = url.trim()

  // `git@hôte:` est la forme SSH ordinaire, sans mot de passe.
  if (/^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:/.test(trimmed)) {
    return false
  }

  try {
    const parsed = new URL(trimmed)
    return parsed.username !== '' || parsed.password !== ''
  } catch {
    return false
  }
}

/** Un remote, réduit à ce qui peut être affiché et journalisé. */
export interface SafeRemote {
  readonly name: string
  readonly host: string | null
  /** Hôte et chemin, sans identifiants. `null` si non interprétable. */
  readonly url: string | null
}

/**
 * Réduit un remote à sa forme sûre.
 *
 * Le nom (`origin`, `upstream`) est repris tel quel : il est choisi
 * localement et ne porte pas d'identifiant. L'URL, elle, ne survit que
 * sous forme expurgée.
 */
export function toSafeRemote(remote: {
  readonly name?: string | undefined
  readonly fetchUrl?: string | undefined
  readonly pushUrl?: string | undefined
}): SafeRemote {
  const raw = remote.fetchUrl ?? remote.pushUrl
  return {
    name: remote.name ?? 'origin',
    host: remoteHostOf(raw),
    url: sanitizeRemoteUrl(raw),
  }
}
