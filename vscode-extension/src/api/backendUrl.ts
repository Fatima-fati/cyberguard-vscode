/**
 * Validation de l'adresse du backend.
 *
 * Pourquoi ce module existe
 * -------------------------
 *
 * `wazuhSecurity.backendUrl` décide où part le **contenu intégral** de
 * chaque fichier analysé. C'est le seul chemin d'exfiltration du code de
 * l'utilisateur, et il était exploitable par un dépôt cloné :
 *
 *     1. le développeur clone un dépôt tiers
 *     2. `.vscode/settings.json` y contient
 *        "wazuhSecurity.backendUrl": "https://attaquant.example"
 *     3. le développeur fait confiance au workspace (geste réflexe)
 *     4. à chaque sauvegarde, le fichier entier part chez l'attaquant
 *
 * L'extension se comporterait exactement comme prévu. Trois défenses,
 * complémentaires :
 *
 * - `"scope": "machine"` dans le manifeste — le réglage n'est plus
 *   modifiable par `.vscode/settings.json` ;
 * - `capabilities.untrustedWorkspaces.restrictedConfigurations` — VS Code
 *   ignore explicitement ce réglage dans un workspace non fiable ;
 * - **ce module** — une adresse non locale exige un accord explicite, et
 *   une adresse malformée est refusée avec un diagnostic.
 *
 * Les trois sont nécessaires : les deux premières dépendent de la
 * configuration du manifeste, la troisième vaut quel que soit le chemin
 * par lequel l'adresse arrive.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import { FR } from '../i18n/fr'

/** Adresse par défaut : la boucle locale, le cas normal. */
export const DEFAULT_BACKEND_URL = 'http://127.0.0.1:8000'

/**
 * Hôtes considérés comme locaux.
 *
 * `0.0.0.0` n'y figure pas : c'est une adresse d'écoute, pas une adresse
 * de destination. L'accepter comme « locale » reviendrait à valider une
 * URL qui, selon la pile réseau, peut joindre autre chose que la machine.
 */
const LOCAL_HOSTNAMES: ReadonlySet<string> = new Set([
  'localhost',
  '127.0.0.1',
  '::1',
  '[::1]',
])

/** Protocoles admis. Rien d'autre : ni `file:`, ni `ws:`, ni `data:`. */
const ALLOWED_PROTOCOLS: ReadonlySet<string> = new Set(['http:', 'https:'])

export type BackendUrlRejection =
  /** Chaîne vide ou uniquement des blancs. */
  | 'empty'
  /** `new URL()` a refusé la chaîne. */
  | 'malformed'
  /** Protocole autre que http/https. */
  | 'protocol'
  /** Identifiants dans l'URL (`http://user:pass@hôte`). */
  | 'credentials'
  /** Hôte absent. */
  | 'noHost'
  /** Chemin, requête ou fragment : le backend est une origine, pas une page. */
  | 'notAnOrigin'
  /** Hôte distant, alors que les backends distants ne sont pas autorisés. */
  | 'remoteNotAllowed'

export type BackendUrlVerdict =
  | {
      readonly ok: true
      /** Adresse normalisée, sans slash final. À utiliser telle quelle. */
      readonly url: string
      /** L'hôte est-il la machine locale ? */
      readonly local: boolean
      /** Hôte seul, pour l'affichage. Jamais l'URL complète. */
      readonly host: string
    }
  | {
      readonly ok: false
      readonly reason: BackendUrlRejection
      /** Message déjà traduit, affichable tel quel. */
      readonly message: string
    }

export interface BackendUrlOptions {
  /**
   * L'utilisateur a-t-il explicitement autorisé un backend distant ?
   *
   * Réglage distinct, `machine`-scopé lui aussi : il faut deux gestes
   * délibérés pour envoyer du code hors de la machine, et aucun dépôt
   * cloné ne peut en accomplir un seul.
   */
  readonly allowRemote?: boolean
}

/**
 * Un hôte est-il local ?
 *
 * Tout le bloc `127.0.0.0/8` est accepté : `127.0.0.1` est l'usage
 * courant, mais `127.0.1.1` est la boucle locale sur certaines
 * distributions. La vérification reste textuelle et stricte — aucune
 * résolution DNS n'est tentée, parce qu'un nom qui résout aujourd'hui vers
 * `127.0.0.1` peut résoudre demain vers autre chose, et parce qu'une
 * résolution rendrait la validation dépendante du réseau.
 */
export function isLocalHost(hostname: string): boolean {
  const host = hostname.trim().toLowerCase()
  if (LOCAL_HOSTNAMES.has(host)) {
    return true
  }
  // `new URL()` conserve les crochets IPv6 dans `host` mais pas dans
  // `hostname` : les deux formes sont donc couvertes.
  const bare = host.replace(/^\[|\]$/g, '')
  if (bare === '::1') {
    return true
  }
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(bare)
}

/**
 * Valide et normalise une adresse de backend.
 *
 * En cas de refus, **aucune adresse n'est proposée en remplacement** :
 * l'appelant décide quoi faire, et le message explique quoi corriger.
 * Retourner discrètement une adresse par défaut masquerait une
 * configuration hostile derrière un fonctionnement apparemment normal.
 */
export function validateBackendUrl(
  raw: string,
  options: BackendUrlOptions = {}
): BackendUrlVerdict {
  const candidate = (raw ?? '').trim()

  if (!candidate) {
    return { ok: false, reason: 'empty', message: FR.backendUrl.empty }
  }

  let parsed: URL
  try {
    parsed = new URL(candidate)
  } catch {
    return {
      ok: false,
      reason: 'malformed',
      message: FR.backendUrl.malformed(candidate),
    }
  }

  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    return {
      ok: false,
      reason: 'protocol',
      message: FR.backendUrl.protocol(parsed.protocol),
    }
  }

  // Des identifiants dans l'URL partiraient dans chaque requête et
  // finiraient dans les journaux des intermédiaires. Refusé sans
  // exception : il n'existe aucune raison légitime d'en mettre ici, le
  // backend s'authentifie par en-tête.
  if (parsed.username || parsed.password) {
    return {
      ok: false,
      reason: 'credentials',
      message: FR.backendUrl.credentials,
    }
  }

  if (!parsed.hostname) {
    return { ok: false, reason: 'noHost', message: FR.backendUrl.noHost }
  }

  // Le backend est une origine, pas une page. Un chemin de base changerait
  // la cible de toutes les routes construites ailleurs (`/api/code/...`)
  // et ouvrirait un détournement discret : `http://127.0.0.1:8000/../..`
  // n'est pas la même destination que l'origine annoncée.
  if ((parsed.pathname && parsed.pathname !== '/') || parsed.search || parsed.hash) {
    return {
      ok: false,
      reason: 'notAnOrigin',
      message: FR.backendUrl.notAnOrigin,
    }
  }

  const local = isLocalHost(parsed.hostname)

  if (!local && options.allowRemote !== true) {
    return {
      ok: false,
      reason: 'remoteNotAllowed',
      message: FR.backendUrl.remoteNotAllowed(parsed.host),
    }
  }

  // `origin` plutôt que la chaîne d'origine : la sortie est normalisée
  // (casse de l'hôte, port par défaut retiré) et ne peut pas contenir de
  // reste de chemin.
  return { ok: true, url: parsed.origin, local, host: parsed.host }
}

/**
 * Faut-il signaler l'adresse dans la barre d'état ?
 *
 * Un backend local est le cas normal et n'a pas besoin d'être annoncé. Un
 * backend distant doit rester visible en permanence : c'est l'indice qui
 * permet de s'apercevoir que le code part ailleurs.
 */
export function shouldAdvertiseBackend(verdict: BackendUrlVerdict): boolean {
  return verdict.ok && !verdict.local
}
