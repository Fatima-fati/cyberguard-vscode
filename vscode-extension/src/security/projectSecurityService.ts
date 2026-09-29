/**
 * Orchestration de la sécurité projet côté extension.
 *
 * Responsabilités séparées, dans cet ordre :
 *
 *     secretScanner.ts          détecte          (aucun état, aucune E/S)
 *     dependencyInventory.ts    inventorie       (aucun état, aucune E/S)
 *     projectSecurityService.ts orchestre        (cet état)
 *     backendClient.ts          parle HTTP       (aucun état métier)
 *
 * Ce module ne détecte rien et ne parcourt aucun dossier : il reçoit les
 * accumulateurs remplis pendant la découverte, les soumet au backend et
 * conserve la seule copie vivante du résultat.
 *
 * Trois garanties tenues ici
 * --------------------------
 *
 * - **rien n'est envoyé en clair** : les accumulateurs ne contiennent que
 *   des preuves déjà expurgées, et un contrôle de dernière minute refuse
 *   d'envoyer un lot qui n'en serait pas ;
 * - **un échec partiel ne perd pas le reste** : secrets et dépendances
 *   sont soumis séparément, et l'échec de l'un n'annule pas l'autre ;
 * - **jamais silencieux** : chaque issue produit un message destiné à
 *   l'utilisateur, y compris « le fournisseur n'a pas répondu ».
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import type { BackendClient } from '../api/backendClient'
import { BackendError } from '../api/backendClient'
import { FR } from '../i18n/fr'
import { isRedacted } from './redaction'
import { ENGINE_NAME, ENGINE_VERSION, type ProjectSecretScan } from './secretScanner'
import { INVENTORY_VERSION, type ProjectInventory } from './dependencyInventory'
import {
  ENGINE_NAME as API_ENGINE_NAME,
  ENGINE_VERSION as API_ENGINE_VERSION,
  type ProjectApiScan,
} from '../apisec/apiScanner'
import type {
  ApiScanResult,
  DependencyScanResult,
  SecretScanResult,
  SecurityFinding,
} from './securityTypes'

export interface ProjectSecurityOptions {
  readonly client: BackendClient
  readonly log: (message: string) => void
}

/** Ce que l'appelant a collecté pendant la découverte. */
export interface ProjectSecurityInput {
  readonly projectUid: string
  readonly secrets: ProjectSecretScan
  readonly inventory: ProjectInventory
  /** Analyse de sécurité d'API (phase 5). Absente = rien à soumettre. */
  readonly api?: ProjectApiScan
  /** L'utilisateur autorise-t-il l'interrogation de la base publique ? */
  readonly checkVulnerabilities: boolean
  /**
   * Soumettre le balayage de secrets. Défaut : oui.
   *
   * Introduit par la surveillance continue (phase 3), et par défaut sans
   * effet : une découverte complète soumet toujours les deux.
   *
   * Le besoin est précis. Quand un seul `.py` change, son inventaire de
   * dépendances n'a pas bougé d'un octet ; le resoumettre ferait
   * réinterroger la base publique de vulnérabilités pour un résultat
   * identique. Le réglage de l'utilisateur n'autorise cette sortie réseau
   * que parce qu'elle apprend quelque chose — la déclencher pour rien
   * serait en abuser.
   */
  readonly submitSecrets?: boolean
  /** Soumettre l'inventaire des dépendances. Défaut : oui. */
  readonly submitDependencies?: boolean
  /**
   * Soumettre l'analyse d'API. Défaut : **non**.
   *
   * Contrairement aux deux autres, ce drapeau est faux par défaut : la
   * phase 5 s'ajoute à une chaîne existante, et un appelant qui ignore
   * l'API ne doit pas en déclencher l'envoi sans le savoir.
   */
  readonly submitApi?: boolean
}

export interface ProjectSecurityOutcome {
  /** Au moins une des deux soumissions a abouti. */
  readonly ok: boolean
  readonly secrets: SecretScanResult | undefined
  readonly dependencies: DependencyScanResult | undefined
  readonly api: ApiScanResult | undefined
  /** Tous les findings, secrets et dépendances confondus. */
  readonly findings: SecurityFinding[]
  /** Message destiné à l'utilisateur. Toujours présent. */
  readonly message: string
  readonly warnings: string[]
}

export class ProjectSecurityService {
  private readonly client: BackendClient
  private readonly log: (message: string) => void

  private secrets: SecretScanResult | undefined
  private dependencies: DependencyScanResult | undefined
  private api: ApiScanResult | undefined
  private running = false

  constructor(options: ProjectSecurityOptions) {
    this.client = options.client
    this.log = options.log
  }

  get isRunning(): boolean {
    return this.running
  }

  /** Dernier résultat de balayage de secrets, si un balayage a abouti. */
  secretResult(): SecretScanResult | undefined {
    return this.secrets
  }

  /** Dernier résultat d'inventaire, si un inventaire a abouti. */
  dependencyResult(): DependencyScanResult | undefined {
    return this.dependencies
  }

  /** Dernier résultat d'analyse d'API, si une analyse a abouti. */
  apiResult(): ApiScanResult | undefined {
    return this.api
  }

  /** Oublie les résultats : changement de dossier, ou vidage de la vue. */
  clear(): void {
    this.secrets = undefined
    this.dependencies = undefined
    this.api = undefined
  }

  /**
   * Soumet ce qui a été collecté et retourne ce que le backend en dit.
   *
   * Les deux soumissions sont **séquentielles et indépendantes** : un
   * backend qui refuse l'inventaire ne doit pas faire perdre le balayage
   * de secrets, qui est la partie la plus urgente des deux.
   */
  async submit(input: ProjectSecurityInput): Promise<ProjectSecurityOutcome> {
    this.running = true
    const warnings: string[] = []

    try {
      const secrets = await this.submitSecrets(input, warnings)
      const api = await this.submitApi(input, warnings)
      const dependencies = await this.submitDependencies(input, warnings)

      const ok =
        secrets !== undefined || dependencies !== undefined || api !== undefined
      return {
        ok,
        secrets,
        dependencies,
        api,
        findings: [
          ...(secrets?.findings ?? []),
          ...(api?.findings ?? []),
          ...(dependencies?.findings ?? []),
        ],
        message: this.summarize(secrets, dependencies, api, ok),
        warnings,
      }
    } finally {
      this.running = false
    }
  }

  /**
   * Relit les findings déjà enregistrés, sans nouveau balayage.
   *
   * Sert au démarrage d'un projet déjà connu : afficher ce qu'on savait de
   * la session précédente vaut mieux qu'une vue vide. Un 404 est une
   * réponse normale — projet jamais balayé.
   */
  async fetchExisting(projectUid: string): Promise<SecurityFinding[]> {
    try {
      return await this.client.listProjectFindings(projectUid, { status: 'open' })
    } catch (error) {
      if (error instanceof BackendError && error.status === 404) {
        return []
      }
      this.log(`reprise des findings de sécurité impossible : ${describe(error)}`)
      return []
    }
  }

  // ---------------- Interne ----------------

  private async submitSecrets(
    input: ProjectSecurityInput,
    warnings: string[]
  ): Promise<SecretScanResult | undefined> {
    if (input.submitSecrets === false) {
      // Non demandé : on rend le dernier résultat connu plutôt que
      // `undefined`, pour que l'appelant distingue « pas soumis cette
      // fois » de « soumission refusée ».
      return this.secrets
    }

    const findings = input.secrets.findings.filter((finding) => {
      if (isRedacted(finding.evidence_redacted)) {
        return true
      }
      // Contrôle de dernière minute. Un signalement dont la preuve n'est
      // pas expurgée est **écarté**, pas corrigé en silence : c'est le
      // signe d'un défaut du moteur, et l'envoyer ferait sortir une valeur
      // de la machine.
      this.log(
        `signalement écarté avant envoi : preuve non expurgée ` +
          `(${finding.rule_id}, ${finding.file_path})`
      )
      return false
    })

    try {
      const result = await this.client.submitSecretScan(input.projectUid, {
        findings,
        scanned_files: input.secrets.scannedFiles,
        skipped_files: input.secrets.skippedFiles,
        engine: ENGINE_NAME,
        engine_version: ENGINE_VERSION,
        truncated: input.secrets.truncated,
        warnings: [],
      })

      this.secrets = result
      // Volumes seulement : aucun chemin de secret, aucune preuve.
      this.log(
        `balayage de secrets soumis — ${input.secrets.scannedFiles} fichier(s) ` +
          `analysé(s), ${result.statistics.total} signalement(s) retenu(s) ` +
          `dans ${result.statistics.files_with_secrets} fichier(s)` +
          (input.secrets.truncated ? ' [tronqué]' : '')
      )
      warnings.push(...result.warnings)
      return result
    } catch (error) {
      this.log(`balayage de secrets refusé par le backend : ${describe(error)}`)
      warnings.push(FR.security.secretsFailed(describe(error)))
      return undefined
    }
  }

  /**
   * Soumet l'analyse de sécurité d'API.
   *
   * Absente ou non demandée : on rend le dernier résultat connu, pour que
   * l'appelant distingue « pas soumis cette fois » de « soumission
   * refusée ». Un échec n'annule ni les secrets ni l'inventaire.
   */
  private async submitApi(
    input: ProjectSecurityInput,
    warnings: string[]
  ): Promise<ApiScanResult | undefined> {
    if (input.submitApi !== true || !input.api) {
      return this.api
    }

    try {
      const result = await this.client.submitApiScan(input.projectUid, {
        findings: input.api.findings,
        scanned_files: input.api.scannedFiles,
        endpoints_detected: input.api.endpointsDetected,
        engine: API_ENGINE_NAME,
        engine_version: API_ENGINE_VERSION,
        truncated: input.api.truncated,
        warnings: [],
      })

      this.api = result
      // Volumes seulement : aucun chemin de route, aucun extrait.
      this.log(
        `analyse d'API soumise — ${input.api.scannedFiles} fichier(s) ` +
          `analysé(s), ${result.statistics.endpoints_detected} route(s) ` +
          `relevée(s), ${result.statistics.total} signalement(s) retenu(s)` +
          (input.api.truncated ? ' [tronqué]' : '')
      )
      warnings.push(...result.warnings)
      return result
    } catch (error) {
      this.log(`analyse d'API refusée par le backend : ${describe(error)}`)
      warnings.push(FR.api.submissionFailed(describe(error)))
      return undefined
    }
  }

  private async submitDependencies(
    input: ProjectSecurityInput,
    warnings: string[]
  ): Promise<DependencyScanResult | undefined> {
    if (input.submitDependencies === false) {
      return this.dependencies
    }

    try {
      const result = await this.client.submitDependencyInventory(input.projectUid, {
        dependencies: input.inventory.dependencies,
        manifests_read: input.inventory.manifestsRead,
        truncated: input.inventory.truncated,
        warnings: [],
        inventory_version: INVENTORY_VERSION,
        check_vulnerabilities: input.checkVulnerabilities,
      })

      this.dependencies = result
      this.log(
        `inventaire des dépendances soumis — ${result.dependency_statistics.total} ` +
          `dépendance(s) dont ${result.dependency_statistics.direct} directe(s), ` +
          `fournisseur « ${result.vulnerability_statistics.provider} » : ` +
          `${result.vulnerability_statistics.provider_status}, ` +
          `${result.vulnerability_statistics.total} vulnérabilité(s), ` +
          `${result.dependency_statistics.unverified} dépendance(s) non vérifiée(s)`
      )
      warnings.push(...result.warnings)
      return result
    } catch (error) {
      this.log(`inventaire des dépendances refusé par le backend : ${describe(error)}`)
      warnings.push(FR.security.dependenciesFailed(describe(error)))
      return undefined
    }
  }

  /**
   * Compose le message affiché à l'utilisateur.
   *
   * La phrase sur les vulnérabilités vient **du backend**
   * (`vulnerability_statistics.message`) et n'est jamais reformulée ici :
   * c'est ce qui garantit qu'aucun chemin de code côté extension ne peut
   * écrire « aucune vulnérabilité » à partir d'un fournisseur muet.
   */
  private summarize(
    secrets: SecretScanResult | undefined,
    dependencies: DependencyScanResult | undefined,
    api: ApiScanResult | undefined,
    ok: boolean
  ): string {
    if (!ok) {
      return FR.security.scanFailed
    }

    const parts: string[] = []

    if (secrets) {
      parts.push(
        FR.security.secretsSummary(
          secrets.statistics.total,
          secrets.statistics.files_with_secrets,
          secrets.statistics.scanned_files
        )
      )
    }

    if (api) {
      parts.push(
        FR.api.summary(
          api.statistics.total,
          api.statistics.endpoints_detected,
          api.statistics.scanned_files
        )
      )
    }

    if (dependencies) {
      parts.push(
        FR.security.dependenciesSummary(
          dependencies.dependency_statistics.total,
          dependencies.dependency_statistics.direct
        )
      )
      // Message rédigé par le backend, repris tel quel.
      parts.push(dependencies.vulnerability_statistics.conclusive
        ? FR.security.vulnerabilitiesSummary(
            dependencies.vulnerability_statistics.total,
            dependencies.dependency_statistics.unverified
          )
        : dependencies.vulnerability_statistics.message)
    }

    return parts.join(' ')
  }
}

function describe(error: unknown): string {
  if (error instanceof BackendError) {
    return error.message
  }
  return error instanceof Error ? error.message : FR.errors.unexpected
}
