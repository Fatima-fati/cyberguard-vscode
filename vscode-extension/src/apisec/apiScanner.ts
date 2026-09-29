/**
 * Moteur d'analyse de sécurité d'API. Déterministe, local, borné.
 *
 * Même architecture que `secretScanner.ts`, dont il reprend les
 * conventions : le texte est fourni par l'appelant, rien n'est lu ici,
 * rien n'est journalisé, et seul un constat expurgé sort.
 *
 * Ce qu'il produit, et ce qu'il refuse de produire
 * ------------------------------------------------
 *
 *     PRODUIT   un constat motivé : quelle route, quelle ligne, quelle
 *               règle, quelle preuve, quelle confiance
 *     REFUSE    « cette API est vulnérable » quand la preuve montre
 *               seulement « l'authentification n'est pas visible ici »
 *
 * Cette distinction est le cœur de la phase. Une analyse par lignes ne
 * voit que le fichier qu'on lui donne : une authentification posée par un
 * middleware monté ailleurs lui est invisible. Trois garde-fous en
 * découlent :
 *
 * 1. **l'authentification globale fait taire la règle.** Un fichier qui
 *    monte `app.use(requireAuth)` ne produit aucun « endpoint non
 *    authentifié » ;
 * 2. **seules les routes qui comptent sont signalées.** Une lecture
 *    (`GET`) sur un chemin banal ne produit rien ; une écriture, ou un
 *    chemin d'administration, oui ;
 * 3. **la confiance est dite, et elle plafonne la gravité.** Le backend
 *    applique `apply_confidence` : une détection moyennement sûre ne
 *    s'affiche jamais en CRITICAL.
 *
 * Bornes, et pourquoi chacune
 * ---------------------------
 *
 *     lignes par fichier     un fichier généré ne doit pas monopoliser
 *                            le balayage
 *     longueur de ligne      un bundle minifié tient sur une ligne de
 *                            500 000 caractères
 *     findings par fichier   un fichier de routes en produirait des
 *                            dizaines d'identiques
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import { looksLikeDocumentation } from '../security/falsePositives'
import { cappedSeverity, isLowTrustPath, downgrade } from '../security/falsePositives'
import type {
  ApiFindingSubmission,
  Confidence,
  Severity,
} from '../security/securityTypes'
import {
  LINE_RULES,
  RULE_MISSING_AUTHORIZATION,
  RULE_PUBLIC_STATE_CHANGE,
  RULE_SENSITIVE_PUBLIC,
  RULE_UNAUTHENTICATED,
  isSensitivePath,
  type ApiRule,
} from './apiRules'
import {
  STATE_CHANGING,
  condense,
  detectRoutes,
  frameworksForPath,
  hasGlobalAuth,
  type DetectedRoute,
} from './routeDetectors'

/** Nom du moteur, enregistré avec chaque finding. */
export const ENGINE_NAME = 'api-scanner'
/** Version des règles. Change dès qu'un motif change. */
export const ENGINE_VERSION = '1.0.0'

/** Au-delà, le fichier n'est plus analysé et la troncature est annoncée. */
export const MAX_LINES_PER_FILE = 10_000

/** Au-delà, la ligne est ignorée : c'est du code minifié ou généré. */
export const MAX_LINE_LENGTH = 2_000

/** Au-delà, le fichier cesse d'être analysé : il est atypique. */
export const MAX_FINDINGS_PER_FILE = 25

/** Fichiers dont la forme rend l'analyse inexploitable. */
const GENERATED_FILE = /\.(min\.js|min\.css|bundle\.js|map|lock)$/i

/** Extensions de configuration où les règles de ligne s'appliquent aussi. */
const CONFIG_EXTENSIONS: ReadonlySet<string> = new Set([
  '.json',
  '.yaml',
  '.yml',
  '.toml',
  '.ini',
  '.cfg',
  '.conf',
  '.properties',
  '.xml',
  '.env',
  '.tf',
])

export interface ApiScanOptions {
  readonly maxLines?: number
  readonly maxLineLength?: number
  readonly maxFindings?: number
}

export interface ApiScanOutcome {
  readonly findings: ApiFindingSubmission[]
  /** Le fichier a-t-il été analysé en entier ? */
  readonly truncated: boolean
  /** Routes relevées, y compris celles qui ne posent aucun problème. */
  readonly routes: readonly DetectedRoute[]
}

/** Ce fichier peut-il porter une route ou une configuration d'API ? */
export function isApiRelevant(relativePath: string): boolean {
  if (GENERATED_FILE.test(relativePath)) {
    return false
  }
  if (frameworksForPath(relativePath).length > 0) {
    return true
  }
  const dot = relativePath.lastIndexOf('.')
  return dot >= 0 && CONFIG_EXTENSIONS.has(relativePath.slice(dot).toLowerCase())
}

/**
 * Analyse un texte déjà lu.
 *
 * L'appelant a décidé que ce fichier pouvait être lu — la phase 1 écarte
 * déjà `.env`, les clés privées et les fichiers d'identifiants. Ce moteur
 * ne rouvre jamais cette décision.
 */
export function scanForApiIssues(
  relativePath: string,
  text: string,
  options: ApiScanOptions = {}
): ApiScanOutcome {
  const maxLines = options.maxLines ?? MAX_LINES_PER_FILE
  const maxLineLength = options.maxLineLength ?? MAX_LINE_LENGTH
  const maxFindings = options.maxFindings ?? MAX_FINDINGS_PER_FILE

  if (!text || !isApiRelevant(relativePath)) {
    return { findings: [], truncated: false, routes: [] }
  }

  const allLines = text.split(/\r?\n/)
  const truncatedByLines = allLines.length > maxLines
  const lines = truncatedByLines ? allLines.slice(0, maxLines) : allLines

  const findings: ApiFindingSubmission[] = []
  let truncated = truncatedByLines

  // Un fichier de test ou d'exemple décrit des routes, il n'en expose
  // pas : la confiance y est systématiquement abaissée.
  const lowTrust = isLowTrustPath(relativePath)

  // --- Routes -----------------------------------------------------------
  const routes = detectRoutes(relativePath, lines)
  const global = hasGlobalAuth(text)

  for (const route of routes) {
    if (findings.length >= maxFindings) {
      truncated = true
      break
    }
    const produced = judgeRoute(route, global, relativePath, lowTrust)
    if (produced) {
      findings.push(produced)
    }
  }

  // --- Règles de ligne --------------------------------------------------
  for (let index = 0; index < lines.length; index += 1) {
    if (findings.length >= maxFindings) {
      truncated = true
      break
    }

    const line = lines[index] ?? ''
    if (line.length > maxLineLength || looksLikeDocumentation(line)) {
      continue
    }

    for (const rule of LINE_RULES) {
      const match = rule.pattern.exec(line)
      if (!match) {
        continue
      }
      if (rule.unless?.test(line)) {
        // Motif d'annulation : un `DEBUG = True` derrière un `if`, ou une
        // URL `http://` qui est un espace de noms XML.
        continue
      }
      // `confirmedBy` cherche dans tout le fichier : la confirmation est
      // rarement sur la même ligne que le motif (`allow_credentials` est
      // presque toujours une ligne plus bas que `allow_origins`).
      if (rule.confirmedBy && !rule.confirmedBy.test(text)) {
        continue
      }
      // Une règle dont la version confirmée s'applique ne doit pas
      // produire aussi sa version faible.
      if (isSupersededHere(rule, line, text)) {
        continue
      }

      // `isPlaceholder` n'est **pas** appliqué ici, et c'est délibéré :
      // il est conçu pour une valeur de secret isolée, et sur un extrait
      // de déclaration entier il écarte toute URL contenant
      // `example.com` — ce qui faisait taire les règles de transport et
      // d'identifiants au complet. Le bruit est filtré en amont, par
      // `unless` et par `looksLikeDocumentation`.
      const evidence = condense(match[0])

      const confidence = lowTrust ? downgrade(rule.confidence) : rule.confidence
      findings.push(
        submission({
          rule,
          relativePath,
          line: index + 1,
          evidence,
          confidence,
          endpoint: '',
          method: '',
        })
      )
      // Une ligne ne produit qu'un constat : la première règle qui
      // correspond gagne. Les règles fortes sont déclarées avant les
      // faibles, et l'ordre porte donc cette décision.
      break
    }
  }

  return { findings, truncated, routes }
}

// --------------------------------------------------------------------------
// Jugement d'une route
// --------------------------------------------------------------------------

/**
 * Cette route mérite-t-elle un signalement ?
 *
 * Renvoie `null` dans l'immense majorité des cas — et c'est voulu. Une
 * route correctement protégée, ou une simple lecture sur un chemin banal,
 * ne produit rien.
 */
function judgeRoute(
  route: DetectedRoute,
  global: { found: boolean; evidence: string },
  relativePath: string,
  lowTrust: boolean
): ApiFindingSubmission | null {
  const stateChanging = STATE_CHANGING.has(route.method) || route.method === 'ANY'
  const sensitive = isSensitivePath(route.path)

  // --- Route explicitement publique -------------------------------------
  //
  // Traité en premier : c'est le cas de confiance la plus élevée, parce
  // que la décision est écrite dans le code. Une authentification globale
  // ne l'annule pas — `AllowAny` est précisément ce qui s'en affranchit.
  if (route.explicitlyPublic && (stateChanging || sensitive)) {
    return submission({
      rule: RULE_PUBLIC_STATE_CHANGE,
      relativePath,
      line: route.line,
      evidence: `${route.evidence} — ${route.publicEvidence ?? ''}`.trim(),
      confidence: lowTrust ? downgrade(RULE_PUBLIC_STATE_CHANGE.confidence) : RULE_PUBLIC_STATE_CHANGE.confidence,
      endpoint: route.path,
      method: route.method,
      framework: route.framework,
    })
  }

  // --- Authentification absente -----------------------------------------
  if (!route.authenticated) {
    // Le garde-fou décisif : une authentification posée pour toute
    // l'application fait taire la règle. Sans lui, un projet qui protège
    // correctement ses routes recevrait un signalement par route.
    if (global.found) {
      return null
    }
    // Une lecture sur un chemin banal ne prouve rien : beaucoup d'API
    // exposent légitimement des routes publiques en lecture.
    if (!stateChanging && !sensitive) {
      return null
    }

    const rule = sensitive && !stateChanging ? RULE_SENSITIVE_PUBLIC : RULE_UNAUTHENTICATED
    return submission({
      rule,
      relativePath,
      line: route.line,
      evidence: route.evidence,
      confidence: lowTrust ? downgrade(rule.confidence) : rule.confidence,
      endpoint: route.path,
      method: route.method,
      framework: route.framework,
    })
  }

  // --- Authentifiée, mais sans contrôle d'autorisation ------------------
  //
  // Réservé aux chemins sensibles : exiger un contrôle de rôle sur
  // chaque route authentifiée produirait du bruit sur des API où tout
  // utilisateur connecté a légitimement accès à tout.
  if (!route.authorized && sensitive) {
    return submission({
      rule: RULE_MISSING_AUTHORIZATION,
      relativePath,
      line: route.line,
      evidence: `${route.evidence} — ${route.authEvidence ?? ''}`.trim(),
      confidence: lowTrust
        ? downgrade(RULE_MISSING_AUTHORIZATION.confidence)
        : RULE_MISSING_AUTHORIZATION.confidence,
      endpoint: route.path,
      method: route.method,
      framework: route.framework,
    })
  }

  return null
}

/**
 * Une règle plus forte couvre-t-elle déjà cette ligne ?
 *
 * Le cas concret : `allow_origins=["*"]` déclenche `API-CORS-001` quand
 * `allow_credentials` est présent dans le fichier, et `API-CORS-002`
 * sinon. Les deux motifs correspondent à la même ligne ; sans ce
 * contrôle, la ligne produirait deux signalements pour un seul problème.
 */
function isSupersededHere(rule: ApiRule, line: string, text: string): boolean {
  if (rule.id !== 'API-CORS-002') {
    return false
  }
  const strong = LINE_RULES.find((candidate) => candidate.id === 'API-CORS-001')
  return (
    strong !== undefined &&
    strong.pattern.test(line) &&
    strong.confirmedBy !== undefined &&
    strong.confirmedBy.test(text)
  )
}

// --------------------------------------------------------------------------
// Construction du constat
// --------------------------------------------------------------------------

function submission(input: {
  rule: ApiRule
  relativePath: string
  line: number
  evidence: string
  confidence: Confidence
  endpoint: string
  method: string
  framework?: string
}): ApiFindingSubmission {
  const severity: Severity = cappedSeverity(input.rule.severity, input.confidence)

  return {
    rule_id: input.rule.id,
    file_path: input.relativePath,
    line: Math.max(1, input.line),
    issue_type: input.rule.issue,
    endpoint: input.endpoint.slice(0, 200),
    http_method: input.method.slice(0, 10),
    framework: (input.framework ?? '').slice(0, 40),
    severity,
    confidence: input.confidence,
    // La preuve est un extrait de **déclaration**, jamais du corps d'un
    // gestionnaire, et elle est condensée sur une ligne.
    evidence: condense(input.evidence),
    title: input.rule.title,
    description: input.rule.description,
    remediation: input.rule.remediation,
    references: [...input.rule.references],
  }
}

// --------------------------------------------------------------------------
// Agrégation sur un projet
// --------------------------------------------------------------------------

export interface ProjectApiScan {
  readonly findings: ApiFindingSubmission[]
  readonly scannedFiles: number
  readonly endpointsDetected: number
  readonly truncated: boolean
}

/**
 * Accumulateur, alimenté fichier par fichier.
 *
 * Même rôle que `SecretScanAccumulator` : la découverte lit déjà chaque
 * fichier éligible pour en calculer l'empreinte, et lui redemander ce
 * texte doublerait les entrées/sorties sans rien apporter.
 */
export class ApiScanAccumulator {
  private readonly findings: ApiFindingSubmission[] = []
  private readonly scannedPaths = new Set<string>()
  private readonly byFile = new Map<string, ApiFindingSubmission[]>()
  private endpoints = 0
  private truncated = false

  private readonly maxFindings: number

  constructor(maxFindings = 500) {
    this.maxFindings = maxFindings
  }

  /** Soumet le contenu d'un fichier déjà lu par l'appelant. */
  consider(relativePath: string, text: string): void {
    if (!isApiRelevant(relativePath)) {
      return
    }
    if (this.findings.length >= this.maxFindings) {
      this.truncated = true
      return
    }

    this.scannedPaths.add(relativePath)
    const outcome = scanForApiIssues(relativePath, text)
    this.endpoints += outcome.routes.length
    if (outcome.truncated) {
      this.truncated = true
    }

    for (const finding of outcome.findings) {
      if (this.findings.length >= this.maxFindings) {
        this.truncated = true
        return
      }
      this.findings.push(finding)
      const batch = this.byFile.get(relativePath)
      if (batch) {
        batch.push(finding)
      } else {
        this.byFile.set(relativePath, [finding])
      }
    }
  }

  result(): ProjectApiScan {
    return {
      // Les plus graves d'abord : c'est l'ordre dans lequel on veut les
      // voir si le lot doit être tronqué côté backend.
      findings: [...this.findings].sort(compareBySeverity),
      scannedFiles: this.scannedPaths.size,
      endpointsDetected: this.endpoints,
      truncated: this.truncated,
    }
  }

  /** Détail par fichier, pour la surveillance continue (phase 3). */
  perFile(): {
    scannedPaths: ReadonlySet<string>
    apiByFile: ReadonlyMap<string, readonly ApiFindingSubmission[]>
    endpointsDetected: number
    truncated: boolean
  } {
    const apiByFile = new Map<string, readonly ApiFindingSubmission[]>()
    for (const [path, findings] of this.byFile) {
      apiByFile.set(path, [...findings])
    }
    return {
      scannedPaths: new Set(this.scannedPaths),
      apiByFile,
      endpointsDetected: this.endpoints,
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
  a: ApiFindingSubmission,
  b: ApiFindingSubmission
): number {
  const bySeverity = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
  if (bySeverity !== 0) {
    return bySeverity
  }
  const byPath = a.file_path.localeCompare(b.file_path)
  return byPath !== 0 ? byPath : a.line - b.line
}
