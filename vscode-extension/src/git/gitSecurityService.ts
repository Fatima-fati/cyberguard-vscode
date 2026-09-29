/**
 * Sécurité des changements Git : l'analyse.
 *
 * Ce module enchaîne des pièces qui existent déjà, et n'en invente
 * aucune :
 *
 *     gitWorkspace.ts        l'état du dépôt, déjà expurgé
 *     diffParser.ts          le diff unifié → lignes ajoutées
 *     secretScanner.ts       phase 2, inchangé
 *     changeAttribution.ts   introduit / préexistant
 *     prePushPolicy.ts       off / warn / block
 *
 * Ce qu'il produit est un **classement** des findings existants, plus un
 * résumé chiffré. Aucun second registre, aucune seconde table, aucune
 * route backend supplémentaire.
 *
 * Trois contraintes tenues ici
 * ----------------------------
 *
 * **Rapide.** La vérification avant `push` vise moins de trois secondes.
 * Elle ne fait donc **aucun aller-retour réseau** : le diff vient de
 * l'API Git, la recherche de secrets tourne en local (des expressions
 * régulières sur les seuls fichiers modifiés), et les findings de projet
 * sont ceux que le registre détient déjà. Le budget est un vrai compte à
 * rebours, vérifié entre chaque étape.
 *
 * **Échec ouvert.** Délai dépassé, API absente, fichier illisible :
 * l'analyse rend un résumé `conclusive: false`, et la politique laisse
 * passer. Un agent qui empêche de pousser quand il tombe en panne est un
 * agent qu'on retire.
 *
 * **Mode réduit.** Au-delà d'un plafond de fichiers modifiés — un
 * `git checkout` de branche, une fusion — seuls les premiers sont
 * analysés, et le résumé le dit. Analyser deux mille fichiers pour
 * répondre en trois secondes n'est pas possible, et prétendre le
 * contraire serait pire que l'annoncer.
 *
 * Aucune dépendance à `vscode` : tout passe par `GitWorkspace`, et ce
 * module est donc testable en Node pur — ce qui compte, parce que ces
 * règles décident si le travail de quelqu'un est interrompu.
 */

import { FR } from '../i18n/fr'
import {
  isNeverRead,
  isBinaryPath,
  type IgnoreMatcher,
} from '../project/projectDiscovery'
import { crossesExcludedDirectory } from '../monitor/changeClassification'
import { scanForSecrets } from '../security/secretScanner'
import type {
  SecretFindingSubmission,
  SecurityFinding,
} from '../security/securityTypes'
import {
  attributeFindings,
  emptySummary,
  tally,
  type AttributedFinding,
  type GitSecuritySummary,
} from './changeAttribution'
import { buildChangedLineIndex, parseUnifiedDiff, type FileDiff } from './diffParser'
import { isIgnored, isUntracked } from './gitStatus'
import type { GitWorkspace, WorkspaceChange } from './gitWorkspace'

/** Plafond de fichiers analysés avant de passer en mode réduit. */
export const DEFAULT_MAX_CHANGED_FILES = 50

/** Budget par défaut d'une analyse. Voir l'objectif des trois secondes. */
export const DEFAULT_BUDGET_MS = 2_500

export interface GitSecurityOptions {
  readonly workspace: GitWorkspace
  /** Findings déjà connus — le registre existant, jamais une copie. */
  readonly knownFindings: () => readonly SecurityFinding[]
  readonly ignore: () => IgnoreMatcher
  readonly maxChangedFiles: () => number
  readonly log: (message: string) => void
  /** Horloge injectable : le budget doit être testable sans attendre. */
  readonly now?: () => number
}

export interface GitAnalysis {
  readonly summary: GitSecuritySummary
  readonly attributed: readonly AttributedFinding[]
  readonly introduced: readonly AttributedFinding[]
  readonly preExisting: readonly AttributedFinding[]
  /** Empreinte de l'état analysé, pour éviter de recommencer pour rien. */
  readonly fingerprint: string
}

export class GitSecurityService {
  private readonly options: GitSecurityOptions
  private latest: GitAnalysis | undefined
  private running = false

  constructor(options: GitSecurityOptions) {
    this.options = options
  }

  /** Dernier résumé connu. Neutre et non concluant tant qu'aucune analyse. */
  summary(): GitSecuritySummary {
    return this.latest?.summary ?? emptySummary()
  }

  latestAnalysis(): GitAnalysis | undefined {
    return this.latest
  }

  get isRunning(): boolean {
    return this.running
  }

  /** Oublie l'analyse : changement de dossier ouvert. */
  clear(): void {
    this.latest = undefined
  }

  /**
   * Analyse le changement en cours.
   *
   * Ne lève jamais. Toute panne produit un résumé non concluant, qui se
   * lit « on n'a pas pu vérifier » et jamais « rien à signaler ».
   */
  async analyze(
    request: { readonly budgetMs?: number; readonly signal?: AbortSignal } = {}
  ): Promise<GitAnalysis> {
    const deadline = this.clock() + (request.budgetMs ?? DEFAULT_BUDGET_MS)
    const expired = (): boolean =>
      this.clock() > deadline || request.signal?.aborted === true

    this.running = true
    try {
      return (this.latest = await this.run(deadline, expired))
    } catch (error) {
      // Aucune panne ne remonte à l'appelant : elle devient un résumé
      // non concluant, ce que la politique traite en échec ouvert.
      const detail = error instanceof Error ? error.message : String(error)
      this.options.log(FR.git.analysisFailed(detail))
      return (this.latest = {
        summary: emptySummary({
          repository: true,
          conclusive: false,
          message: FR.git.analysisFailed(detail),
          analyzedAt: new Date().toISOString(),
        }),
        attributed: [],
        introduced: [],
        preExisting: [],
        fingerprint: 'error',
      })
    } finally {
      this.running = false
    }
  }

  // ---------------- Interne ----------------

  private async run(deadline: number, expired: () => boolean): Promise<GitAnalysis> {
    const root = this.options.workspace.root()
    const snapshot = root ? await this.options.workspace.snapshot() : undefined

    if (!root || !snapshot) {
      // Aucun dépôt : ce n'est pas une panne. Le résumé le dit
      // explicitement plutôt que d'afficher des zéros — `conclusive` est
      // vrai, parce qu'on sait de source sûre qu'il n'y a rien à voir.
      return {
        summary: emptySummary({
          repository: false,
          conclusive: true,
          message: FR.git.noRepository,
          analyzedAt: new Date().toISOString(),
        }),
        attributed: [],
        introduced: [],
        preExisting: [],
        fingerprint: 'no-repository',
      }
    }

    const changes = this.collectChanges(snapshot.changes)
    const maxFiles = Math.max(1, this.options.maxChangedFiles())
    const reduced = changes.length > maxFiles
    const considered = reduced ? changes.slice(0, maxFiles) : changes

    if (expired()) {
      return this.timedOut(snapshot, changes.length)
    }

    // --- Diff ------------------------------------------------------------
    let diff = ''
    try {
      diff = await snapshot.diff(considered.map((change) => change.path))
    } catch {
      // Un dépôt sans commit initial fait échouer `diff ... HEAD` : c'est
      // un état normal, pas une panne. Les fichiers non suivis couvrent
      // alors l'essentiel du changement.
      diff = ''
    }

    if (expired()) {
      return this.timedOut(snapshot, changes.length)
    }

    const parsed = parseUnifiedDiff(diff)

    // Les fichiers non suivis n'apparaissent dans aucun diff : Git ne les
    // connaît pas encore. Les ignorer ferait manquer exactement le cas le
    // plus courant — un fichier de configuration qu'on vient de créer.
    const withUntracked = await this.appendUntracked(
      parsed.files,
      considered.filter((change) => isUntracked(change.status))
    )

    // Le mode réduit borne ce qu'on examine, y compris ce que le diff
    // porte : sans ce filtre, le plafond ne servirait à rien.
    const kept = new Set(considered.map((change) => change.path))
    const scoped = reduced
      ? withUntracked.filter((file) => kept.has(file.path))
      : withUntracked

    const index = buildChangedLineIndex(scoped)

    // --- Findings --------------------------------------------------------
    //
    // Deux sources, un seul type. Les findings déjà connus viennent du
    // registre ; la recherche de secrets locale couvre ce qui vient
    // d'être écrit et n'a pas encore été soumis.
    const local = await this.scanChangedFiles(scoped, deadline)
    const combined = dedupe([...this.options.knownFindings(), ...local])
    const attribution = attributeFindings(combined, index)

    const summary: GitSecuritySummary = {
      repository: true,
      branch: snapshot.branch,
      remoteHost: snapshot.remoteHost,
      changedFiles: changes.length,
      addedLines: scoped.reduce((total, file) => total + file.addedCount, 0),
      removedLines: scoped.reduce((total, file) => total + file.removedCount, 0),
      reduced,
      analyzedFiles: scoped.length,
      introduced: tally(attribution.introduced),
      preExisting: tally(attribution.preExisting),
      conclusive: true,
      message: reduced ? FR.git.reducedMode(scoped.length, changes.length) : '',
      analyzedAt: new Date().toISOString(),
    }

    // Volumes et branche seulement : aucun chemin de secret, aucune
    // preuve, aucune URL de remote.
    this.options.log(
      FR.git.analysisDone(
        snapshot.branch ?? FR.git.detachedHead,
        summary.changedFiles,
        summary.introduced.total,
        summary.preExisting.total
      )
    )

    return {
      summary,
      attributed: attribution.all,
      introduced: attribution.introduced,
      preExisting: attribution.preExisting,
      fingerprint: snapshot.fingerprint,
    }
  }

  /**
   * Fichiers modifiés retenus pour l'analyse.
   *
   * Les exclusions de la phase 1 s'appliquent telles quelles : un
   * `node_modules` modifié n'intéresse personne, et un fichier ignoré par
   * Git non plus. Le dédoublonnage par chemin évite d'analyser deux fois
   * un fichier partiellement indexé — l'API le liste alors dans
   * `indexChanges` **et** dans `workingTreeChanges`.
   */
  private collectChanges(changes: readonly WorkspaceChange[]): WorkspaceChange[] {
    const ignore = this.options.ignore()
    const seen = new Set<string>()
    const kept: WorkspaceChange[] = []

    for (const change of changes) {
      if (!change.path || seen.has(change.path)) {
        continue
      }
      seen.add(change.path)

      if (isIgnored(change.status)) {
        continue
      }
      if (crossesExcludedDirectory(change.path) || ignore.ignores(change.path)) {
        continue
      }
      kept.push(change)
    }

    // Ordre stable : deux analyses du même état produisent le même
    // résumé, et le mode réduit retient toujours les mêmes fichiers.
    return kept.sort((a, b) => a.path.localeCompare(b.path))
  }

  /**
   * Ajoute les fichiers non suivis comme des fichiers entièrement neufs.
   *
   * Git ne les connaît pas : aucun diff ne les mentionne. Or un fichier
   * qu'on vient de créer est exactement le cas où un secret se glisse.
   * Chacun est décrit comme « ajouté », ce qui rend introduit tout ce
   * qu'il porte.
   */
  private async appendUntracked(
    files: readonly FileDiff[],
    untracked: readonly WorkspaceChange[]
  ): Promise<FileDiff[]> {
    const known = new Set(files.map((file) => file.path))
    const extra: FileDiff[] = []

    for (const change of untracked) {
      if (known.has(change.path)) {
        continue
      }

      const lines = await this.countLines(change.path)
      extra.push({
        path: change.path,
        previousPath: null,
        change: 'added',
        addedRanges: lines > 0 ? [{ start: 1, end: lines }] : [],
        addedCount: lines,
        removedCount: 0,
        binary: isBinaryPath(change.path),
      })
    }

    return [...files, ...extra]
  }

  /**
   * Recherche de secrets sur les seuls fichiers modifiés.
   *
   * Le moteur de la phase 2, inchangé, appliqué à un sous-ensemble. C'est
   * ce qui tient le budget : quelques expressions régulières sur dix
   * fichiers, sans aucun appel réseau.
   *
   * Les règles de lecture de la phase 1 ne sont pas relâchées : un
   * `.env`, un binaire ou un fichier trop volumineux ne sont pas ouverts.
   */
  private async scanChangedFiles(
    files: readonly FileDiff[],
    deadline: number
  ): Promise<SecurityFinding[]> {
    const produced: SecurityFinding[] = []

    for (const file of files) {
      if (this.clock() > deadline) {
        // Budget épuisé : on rend ce qu'on a. Les fichiers analysés
        // l'ont été correctement, et le reste demeure couvert par les
        // findings déjà connus.
        break
      }
      if (file.change === 'deleted' || file.binary) {
        continue
      }
      if (isNeverRead(file.path) || isBinaryPath(file.path)) {
        continue
      }

      const text = await this.options.workspace.readFile(file.path)
      if (text === undefined) {
        continue
      }

      for (const finding of scanForSecrets(file.path, text).findings) {
        produced.push(toSecurityFinding(finding))
      }
    }

    return produced
  }

  private async countLines(relativePath: string): Promise<number> {
    if (isNeverRead(relativePath) || isBinaryPath(relativePath)) {
      // Non lu : on ne connaît pas sa longueur, et un intervalle vide
      // suffit — le fichier reste marqué « ajouté ».
      return 0
    }
    const text = await this.options.workspace.readFile(relativePath)
    return text === undefined ? 0 : text.split(/\r?\n/).length
  }

  private timedOut(
    snapshot: {
      branch: string | null
      remoteHost: string | null
      fingerprint: string
    },
    changedFiles: number
  ): GitAnalysis {
    this.options.log(FR.git.timedOut)
    return {
      summary: emptySummary({
        repository: true,
        branch: snapshot.branch,
        remoteHost: snapshot.remoteHost,
        changedFiles,
        conclusive: false,
        message: FR.git.timedOut,
        analyzedAt: new Date().toISOString(),
      }),
      attributed: [],
      introduced: [],
      preExisting: [],
      fingerprint: snapshot.fingerprint,
    }
  }

  private clock(): number {
    return (this.options.now ?? Date.now)()
  }
}

// --------------------------------------------------------------------------
// Conversion
// --------------------------------------------------------------------------

/**
 * Un constat de secret local, exprimé dans le type unifié.
 *
 * **Ce n'est pas une seconde architecture de findings** : c'est le même
 * `SecurityFinding` que le backend renvoie, rempli localement pour un
 * constat que le backend n'a pas encore vu. Il sert à la décision avant
 * `push` et au résumé ; il n'est ni persisté, ni publié dans le registre
 * — c'est la soumission de la phase 2 qui fait cela, par son chemin.
 *
 * `id` est dérivé du chemin, de la ligne et du **type** de secret, jamais
 * de sa valeur : rien ici ne permet de remonter au secret détecté.
 */
export function toSecurityFinding(
  submission: SecretFindingSubmission
): SecurityFinding {
  return {
    id: `git-local:${submission.file_path}:${submission.line}:${submission.secret_type}`,
    project_uid: '',
    category: 'SECRET',
    severity: submission.severity,
    severity_label: FR.git.severity[submission.severity] ?? submission.severity,
    confidence: submission.confidence,
    confidence_label: submission.confidence,
    category_label: FR.security.labelSecrets,
    title: submission.title,
    description: submission.description,
    file: submission.file_path,
    line_start: submission.line,
    line_end: submission.line,
    // Déjà expurgée par le moteur : c'est la seule forme qui circule.
    evidence: submission.evidence_redacted,
    remediation: submission.remediation,
    references: [...submission.references],
    detection_engine: 'secret-scanner',
    status: 'open',
    status_label: 'Ouvert',
    created_at: new Date().toISOString(),
  }
}

/**
 * Écarte les doublons entre findings connus et constats locaux.
 *
 * Le même secret peut être connu du backend **et** redétecté localement.
 * Le discriminant est ce qui identifie le problème — catégorie, moteur,
 * fichier, ligne — jamais l'identifiant, qui diffère par construction, et
 * **jamais le titre** : le backend nomme un secret depuis son catalogue,
 * le moteur local depuis sa table de motifs. Deux libellés pour un seul
 * problème, et une clé qui les distinguerait afficherait deux fois la
 * même chose. Le premier vu l'emporte : les findings du registre
 * passent en tête, et ce sont eux qui portent le `status` décidé par
 * l'utilisateur.
 */
export function dedupe(findings: readonly SecurityFinding[]): SecurityFinding[] {
  const seen = new Map<string, SecurityFinding>()
  for (const finding of findings) {
    const key = [
      finding.category,
      finding.detection_engine,
      finding.file ?? '',
      finding.line_start,
    ].join('|')
    if (!seen.has(key)) {
      seen.set(key, finding)
    }
  }
  return [...seen.values()]
}
