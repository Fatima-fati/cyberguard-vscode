/**
 * Moteur de détection de secrets. Déterministe, local, borné.
 *
 * Il est la **source de vérité** de la détection : aucune IA n'intervient
 * ici, ni pour décider qu'un secret existe, ni pour en deviner un. Une IA
 * pourra plus tard expliquer et contextualiser ce que ce moteur a trouvé ;
 * elle ne créera jamais une preuve.
 *
 * Ce que ce module ne fait jamais
 * ------------------------------
 *
 *     conserver une valeur      la valeur détectée ne quitte pas la portée
 *                               de `scanLine` ; seul un masque en sort
 *     journaliser une valeur    rien n'est écrit ici, l'appelant ne reçoit
 *                               que des preuves expurgées
 *     lire un fichier           le texte est fourni par l'appelant, qui a
 *                               déjà décidé que ce fichier pouvait être lu
 *     transmettre un fichier    seuls un chemin, une ligne et un masque
 *                               remontent
 *
 * Bornes, et pourquoi chacune
 * ---------------------------
 *
 *     lignes par fichier    un fichier généré ne doit pas monopoliser le
 *                           balayage
 *     longueur de ligne     un bundle minifié tient sur une ligne de
 *                           500 000 caractères ; l'y chercher un secret
 *                           coûte cher et ne trouve que du bruit
 *     findings par fichier  un fichier de fixtures produirait des
 *                           centaines de signalements identiques
 *
 * Aucune borne n'est silencieuse : chaque plafond atteint produit un
 * avertissement remonté à l'utilisateur.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import {
  LOW_ENTROPY_THRESHOLD,
  cappedSeverity,
  downgrade,
  isLowTrustPath,
  isPlaceholder,
  looksLikeDocumentation,
  shannonEntropy,
} from './falsePositives'
import { buildEvidence, isRedacted } from './redaction'
import {
  MIN_ASSIGNED_VALUE_LENGTH,
  PATTERNS_VERSION,
  SECRET_PATTERNS,
} from './secretPatterns'
import type { Confidence, SecretFindingSubmission, Severity } from './securityTypes'

/** Nom du moteur, enregistré avec chaque finding. */
export const ENGINE_NAME = 'secret-scanner'
export const ENGINE_VERSION = PATTERNS_VERSION

/** Au-delà, le fichier n'est plus analysé et la troncature est annoncée. */
export const MAX_LINES_PER_FILE = 10_000

/**
 * Au-delà, la ligne est ignorée.
 *
 * Seuil choisi pour laisser passer du JSON formaté large tout en écartant
 * le code minifié, où un motif d'affectation produirait des dizaines de
 * correspondances sans valeur.
 */
export const MAX_LINE_LENGTH = 2_000

/** Au-delà, le fichier cesse d'être analysé : il est atypique. */
export const MAX_FINDINGS_PER_FILE = 20

/** Fichiers dont la forme rend la détection inexploitable. */
const GENERATED_FILE = /\.(min\.js|min\.css|bundle\.js|map|lock)$/i

export interface SecretScanOptions {
  readonly maxLines?: number
  readonly maxLineLength?: number
  readonly maxFindings?: number
}

export interface FileScanOutcome {
  readonly findings: SecretFindingSubmission[]
  /** Le fichier a-t-il été analysé en entier ? */
  readonly truncated: boolean
}

// --------------------------------------------------------------------------
// Balayage d'un fichier
// --------------------------------------------------------------------------

/**
 * Cherche des secrets dans un texte déjà lu.
 *
 * Le texte est fourni par l'appelant : c'est lui qui a décidé que ce
 * fichier pouvait être lu (`projectDiscovery.isNeverRead` écarte `.env`,
 * les clés privées et les fichiers d'identifiants). Ce moteur ne rouvre
 * jamais cette décision.
 */
export function scanForSecrets(
  relativePath: string,
  text: string,
  options: SecretScanOptions = {}
): FileScanOutcome {
  const maxLines = options.maxLines ?? MAX_LINES_PER_FILE
  const maxLineLength = options.maxLineLength ?? MAX_LINE_LENGTH
  const maxFindings = options.maxFindings ?? MAX_FINDINGS_PER_FILE

  if (!text || GENERATED_FILE.test(relativePath)) {
    return { findings: [], truncated: false }
  }

  const lines = text.split(/\r?\n/)
  const scannable = Math.min(lines.length, maxLines)
  const lowTrustPath = isLowTrustPath(relativePath)

  const findings: SecretFindingSubmission[] = []
  /** `type|ligne` : deux motifs ne signalent pas deux fois le même secret. */
  const seen = new Set<string>()
  let truncated = lines.length > scannable

  for (let index = 0; index < scannable; index += 1) {
    const line = lines[index] ?? ''
    if (line.length === 0 || line.length > maxLineLength) {
      continue
    }

    for (const match of scanLine(relativePath, line, index + 1, lowTrustPath)) {
      const key = `${match.secret_type}|${match.line}`
      if (seen.has(key)) {
        continue
      }
      seen.add(key)
      findings.push(match)

      if (findings.length >= maxFindings) {
        truncated = true
        return { findings, truncated }
      }
    }
  }

  return { findings, truncated }
}

// --------------------------------------------------------------------------
// Balayage d'une ligne
// --------------------------------------------------------------------------

/**
 * Applique tous les motifs à une ligne.
 *
 * **La valeur détectée ne sort pas de cette fonction.** Elle est examinée,
 * pesée, puis remplacée par son masque avant d'entrer dans l'objet
 * retourné. Aucune référence ne lui survit.
 */
function scanLine(
  relativePath: string,
  line: string,
  lineNumber: number,
  lowTrustPath: boolean
): SecretFindingSubmission[] {
  const results: SecretFindingSubmission[] = []
  const documentation = looksLikeDocumentation(line)

  /**
   * Intervalles de la ligne déjà attribués à un motif.
   *
   * Une clé OpenAI est aussi, littéralement, « une valeur affectée à une
   * variable nommée `api_key` » : sans cette réservation, elle produirait
   * deux signalements pour un seul problème, dont un sous un libellé
   * générique moins utile. Les motifs de signature étant évalués en
   * premier, le plus précis réserve la valeur et le plus large la trouve
   * déjà prise.
   */
  const claimed: { start: number; end: number }[] = []

  for (const rule of SECRET_PATTERNS) {
    const match = rule.pattern.exec(line)
    if (!match) {
      continue
    }

    const value = match[rule.valueGroup] ?? match[0] ?? ''
    if (value.length === 0) {
      continue
    }

    const start = line.indexOf(value, match.index)
    const end = start >= 0 ? start + value.length : -1
    if (
      start >= 0 &&
      claimed.some((span) => start < span.end && end > span.start)
    ) {
      continue
    }

    // 1. Rejet — cette valeur ne peut pas être un secret.
    if (isPlaceholder(value)) {
      continue
    }
    if (rule.requiresEntropy && value.length < MIN_ASSIGNED_VALUE_LENGTH) {
      continue
    }

    // 2. Déclassement — la valeur pourrait en être un, le contexte invite
    //    à la prudence. Le finding est conservé : les secrets réels dans
    //    les fixtures et les exemples existent, et les taire créerait un
    //    angle mort.
    let confidence: Confidence = rule.confidence
    if (lowTrustPath) {
      confidence = downgrade(confidence)
    }
    if (documentation) {
      confidence = downgrade(confidence)
    }
    if (rule.requiresEntropy && shannonEntropy(value) < LOW_ENTROPY_THRESHOLD) {
      confidence = downgrade(confidence)
    }

    const severity: Severity = cappedSeverity(rule.severity, confidence)
    const evidence = buildEvidence(rule.label, value, rule.keep)

    // 3. Garde-fou de dernière minute. Une preuve non expurgée ne sort
    //    pas d'ici : mieux vaut un signalement au libellé plus pauvre
    //    qu'une valeur qui fuit vers le backend, la base et l'écran.
    const safeEvidence = isRedacted(evidence)
      ? evidence
      : `${rule.label}: ********`

    if (start >= 0) {
      claimed.push({ start, end })
    }

    results.push({
      rule_id: rule.id,
      file_path: relativePath,
      line: lineNumber,
      column: columnOf(match, line),
      secret_type: rule.secretType,
      severity,
      confidence,
      evidence_redacted: safeEvidence,
      // Le vocabulaire affiché vient du backend, qui le définit une fois
      // pour toutes (`app.security.secret_catalog`). Les laisser vides
      // n'est pas un oubli : c'est ce qui évite deux rédactions
      // divergentes du même message.
      title: '',
      description: '',
      remediation: '',
      references: [],
    })
  }

  return results
}

/**
 * Colonne (0-indexée) où commence la correspondance.
 *
 * Sert au positionnement exact du curseur et du soulignement. `null`
 * plutôt que `0` quand l'information manque : « je ne sais pas » et
 * « première colonne » ne sont pas la même chose, et un soulignement placé
 * au hasard sur la première colonne serait trompeur.
 */
function columnOf(match: RegExpExecArray, line: string): number | null {
  const index = match.index
  if (typeof index !== 'number' || index < 0 || index > line.length) {
    return null
  }
  return index
}

// --------------------------------------------------------------------------
// Agrégation sur un projet
// --------------------------------------------------------------------------

export interface ProjectSecretScan {
  readonly findings: SecretFindingSubmission[]
  readonly scannedFiles: number
  readonly skippedFiles: number
  readonly truncated: boolean
}

/**
 * Accumulateur de balayage, alimenté fichier par fichier.
 *
 * Existe pour une raison précise : la découverte du projet lit déjà chaque
 * fichier éligible pour en calculer l'empreinte. Rendre ce texte au
 * scanner **au moment où il est en main** évite un second parcours complet
 * du disque — sur un monorepo, c'est la différence entre quelques
 * secondes et plusieurs minutes.
 *
 * L'accumulateur ne conserve aucun texte : il reçoit un contenu, en tire
 * des preuves expurgées, et oublie le reste.
 */
export class SecretScanAccumulator {
  private readonly findings: SecretFindingSubmission[] = []
  private scannedFiles = 0
  private skippedFiles = 0
  private truncated = false

  /**
   * Répartition par fichier, pour la surveillance continue (phase 3).
   *
   * Le total agrégé ne suffit pas à cette phase : quand un seul fichier
   * change, il faut pouvoir remplacer **sa** contribution et reconstituer
   * le lot complet sans relire le projet. Le détail est déjà en main ici,
   * au moment où le fichier est analysé — le reconstituer plus tard
   * demanderait un second parcours du disque.
   *
   * Ajout purement additif : `result()` ne change pas d'un octet, et la
   * phase 2 ne consulte jamais ce registre.
   */
  private readonly scannedPaths = new Set<string>()
  private readonly byFile = new Map<string, SecretFindingSubmission[]>()

  private readonly maxFindings: number

  constructor(maxFindings = 500) {
    this.maxFindings = maxFindings
  }

  /** Soumet le contenu d'un fichier déjà lu par l'appelant. */
  consider(relativePath: string, text: string): void {
    if (this.findings.length >= this.maxFindings) {
      this.truncated = true
      this.skippedFiles += 1
      return
    }

    this.scannedFiles += 1
    this.scannedPaths.add(relativePath)
    const outcome = scanForSecrets(relativePath, text)
    if (outcome.truncated) {
      this.truncated = true
    }

    for (const finding of outcome.findings) {
      if (this.findings.length >= this.maxFindings) {
        this.truncated = true
        return
      }
      this.findings.push(finding)
      // Seuls les constats réellement retenus sont enregistrés : le
      // registre doit décrire ce qui a été soumis, pas ce qui aurait pu
      // l'être sans le plafond.
      const batch = this.byFile.get(relativePath)
      if (batch) {
        batch.push(finding)
      } else {
        this.byFile.set(relativePath, [finding])
      }
    }
  }

  /** Note un fichier volontairement non analysé (binaire, sensible, trop gros). */
  skip(): void {
    this.skippedFiles += 1
  }

  result(): ProjectSecretScan {
    return {
      // Les plus graves d'abord : c'est l'ordre dans lequel on veut les
      // voir si le lot doit être tronqué côté backend.
      findings: [...this.findings].sort(compareBySeverity),
      scannedFiles: this.scannedFiles,
      skippedFiles: this.skippedFiles,
      truncated: this.truncated,
    }
  }

  /**
   * Détail par fichier de ce parcours (phase 3).
   *
   * Consommé par `monitor/securityBaseline.ts`, qui en fait l'état de
   * référence de la surveillance continue. Les listes sont copiées : le
   * registre du surveillant vit plus longtemps que l'accumulateur.
   */
  perFile(): {
    scannedPaths: ReadonlySet<string>
    secretsByFile: ReadonlyMap<string, readonly SecretFindingSubmission[]>
    skippedFiles: number
    truncated: boolean
  } {
    const secretsByFile = new Map<string, readonly SecretFindingSubmission[]>()
    for (const [path, findings] of this.byFile) {
      secretsByFile.set(path, [...findings])
    }
    return {
      scannedPaths: new Set(this.scannedPaths),
      secretsByFile,
      skippedFiles: this.skippedFiles,
      truncated: this.truncated,
    }
  }
}

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
}

function compareBySeverity(
  a: SecretFindingSubmission,
  b: SecretFindingSubmission
): number {
  const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
  if (bySeverity !== 0) {
    return bySeverity
  }
  const byPath = a.file_path.localeCompare(b.file_path)
  return byPath !== 0 ? byPath : a.line - b.line
}
