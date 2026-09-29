/**
 * Jeton d'authentification du backend local, côté extension.
 *
 * Le backend génère le jeton au démarrage et l'écrit dans le profil de
 * l'utilisateur. L'extension le lit, le garde dans `SecretStorage`, et le
 * présente à chaque requête.
 *
 *     backend                     extension
 *     -------                     ---------
 *     génère au démarrage
 *     écrit ~/.wazuh-security/
 *            agent-token   ────►  lecture (amorçage)
 *                                 SecretStorage (cache)
 *                                 Authorization: Bearer …
 *
 * Où le jeton n'est **jamais** rangé, et pourquoi
 * ----------------------------------------------
 *
 *     .vscode/settings.json   versionné, lisible par le dépôt
 *     package.json            distribué avec l'extension
 *     code source             distribué avec l'extension
 *     globalState             non chiffré, lisible sur disque
 *
 * `SecretStorage` est la seule réserve de l'API VS Code adossée au
 * trousseau du système. Le fichier d'amorçage reste nécessaire : c'est le
 * seul canal par lequel deux processus indépendants peuvent se mettre
 * d'accord sans configuration manuelle.
 *
 * Le jeton n'apparaît dans aucune trace : les méthodes de ce module
 * rapportent d'où il vient, jamais ce qu'il vaut.
 */

import * as fs from 'node:fs/promises'
import * as os from 'node:os'
import * as path from 'node:path'

/** Clé dans `SecretStorage`. Interne à l'extension. */
const SECRET_KEY = 'wazuhSecurity.agentToken'

/** Réserve de secrets, réduite à ce dont ce module a besoin. */
export interface SecretVault {
  get(key: string): Thenable<string | undefined>
  store(key: string, value: string): Thenable<void>
  delete(key: string): Thenable<void>
}

/** Origine du jeton, pour la trace. Jamais sa valeur. */
export type TokenOrigin = 'secretStorage' | 'tokenFile' | 'none'

export interface TokenResolution {
  readonly token: string | undefined
  readonly origin: TokenOrigin
}

/**
 * Emplacement par défaut du fichier de jeton.
 *
 * Doit correspondre à `app/auth.py:token_path()`. Les deux sont dérivés du
 * profil de l'utilisateur, jamais d'un chemin codé en dur — un chemin
 * absolu spécifique à une machine ne survivrait à aucun autre poste.
 */
export function defaultTokenPath(): string {
  return path.join(os.homedir(), '.wazuh-security', 'agent-token')
}

export interface AgentTokenOptions {
  readonly vault: SecretVault
  /** Remplaçable dans les tests. Par défaut : le chemin du profil. */
  readonly tokenPath?: string
  /** Remplaçable dans les tests. Par défaut : lecture disque. */
  readonly readFile?: (file: string) => Promise<string>
  /** Trace. Ne reçoit jamais la valeur du jeton. */
  readonly onLog?: (message: string) => void
}

export class AgentToken {
  private readonly vault: SecretVault
  private readonly tokenFile: string
  private readonly readFile: (file: string) => Promise<string>
  private readonly onLog: ((message: string) => void) | undefined

  /** Valeur en mémoire pour la durée de la session. */
  private cached: string | undefined
  private origin: TokenOrigin = 'none'

  constructor(options: AgentTokenOptions) {
    this.vault = options.vault
    this.tokenFile = options.tokenPath ?? defaultTokenPath()
    this.readFile =
      options.readFile ?? ((file) => fs.readFile(file, { encoding: 'utf8' }))
    this.onLog = options.onLog
  }

  /**
   * Jeton courant, en le résolvant si nécessaire.
   *
   * Ordre : mémoire, puis `SecretStorage`, puis le fichier. Le fichier
   * n'est lu qu'en dernier — c'est un accès disque, et le cas courant est
   * que le jeton soit déjà connu.
   *
   * Retourne `undefined` si aucun jeton n'est disponible. L'appelant doit
   * alors expliquer la situation, pas échouer silencieusement : un backend
   * éteint et un jeton introuvable demandent deux actions différentes.
   */
  async resolve(): Promise<TokenResolution> {
    if (this.cached) {
      return { token: this.cached, origin: this.origin }
    }

    const stored = await this.readVault()
    if (stored) {
      this.cached = stored
      this.origin = 'secretStorage'
      return { token: stored, origin: 'secretStorage' }
    }

    const fromFile = await this.readTokenFile()
    if (fromFile) {
      this.cached = fromFile
      this.origin = 'tokenFile'
      // Mis en réserve pour les sessions suivantes : le trousseau du
      // système protège mieux qu'un fichier du profil.
      await this.writeVault(fromFile)
      this.log('jeton lu depuis le fichier du backend et mis en réserve')
      return { token: fromFile, origin: 'tokenFile' }
    }

    this.origin = 'none'
    return { token: undefined, origin: 'none' }
  }

  /**
   * Oublie le jeton en mémoire et en réserve, puis le résout à nouveau.
   *
   * Appelé sur un 401 : le backend a pu redémarrer avec un nouveau jeton,
   * auquel cas le fichier porte la valeur à jour et la réserve est
   * périmée. Sans cette reprise, l'extension resterait muette jusqu'au
   * redémarrage de l'éditeur.
   */
  async refresh(): Promise<TokenResolution> {
    this.cached = undefined
    this.origin = 'none'
    await this.clearVault()
    this.log('jeton invalidé, relecture du fichier du backend')
    return this.resolve()
  }

  /** En-tête à joindre à une requête, ou `undefined` si aucun jeton. */
  async authorizationHeader(): Promise<Record<string, string> | undefined> {
    const { token } = await this.resolve()
    return token ? { Authorization: `Bearer ${token}` } : undefined
  }

  /** Emplacement du fichier d'amorçage, pour les messages de diagnostic. */
  get tokenFilePath(): string {
    return this.tokenFile
  }

  // ---------------- Interne ----------------

  private async readVault(): Promise<string | undefined> {
    try {
      const value = await this.vault.get(SECRET_KEY)
      return value?.trim() || undefined
    } catch (error) {
      // Trousseau indisponible (session sans interface graphique, par
      // exemple) : ce n'est pas une panne, le fichier reste utilisable.
      this.log(`réserve de secrets indisponible : ${describe(error)}`)
      return undefined
    }
  }

  private async writeVault(token: string): Promise<void> {
    try {
      await this.vault.store(SECRET_KEY, token)
    } catch (error) {
      this.log(`jeton non mis en réserve : ${describe(error)}`)
    }
  }

  private async clearVault(): Promise<void> {
    try {
      await this.vault.delete(SECRET_KEY)
    } catch (error) {
      this.log(`réserve de secrets non vidée : ${describe(error)}`)
    }
  }

  private async readTokenFile(): Promise<string | undefined> {
    try {
      const raw = await this.readFile(this.tokenFile)
      const value = raw.trim()
      if (!value) {
        this.log('fichier de jeton vide')
        return undefined
      }
      return value
    } catch (error) {
      // Absence normale : le backend n'a jamais démarré sur cette
      // machine. Le chemin est tracé, jamais le contenu.
      this.log(`fichier de jeton illisible (${this.tokenFile}) : ${describe(error)}`)
      return undefined
    }
  }

  private log(message: string): void {
    this.onLog?.(message)
  }
}

/**
 * Description courte d'une erreur, sans trace d'exécution.
 *
 * Le code d'erreur système (`ENOENT`) suffit au diagnostic et ne peut
 * contenir ni jeton ni contenu de fichier.
 */
function describe(error: unknown): string {
  if (error && typeof error === 'object' && 'code' in error) {
    return String((error as { code: unknown }).code)
  }
  return error instanceof Error ? error.name : 'erreur inconnue'
}
