/**
 * Client HTTP du backend FastAPI.
 *
 * L'extension ne parle qu'à `/api/code/*`. Elle ne connaît ni Wazuh
 * Manager API, ni Wazuh Indexer, ni OpenAI, et ne détient aucune
 * information d'identification.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 *
 * Phase 2 : seuls `/api/code/health` et `/api/code/scan` sont utilisés.
 */

import { FR } from '../i18n/fr'
import type {
  ProjectDiscoverSubmission,
  ProjectIndexSubmission,
  ProjectRegistration,
  ProjectSecurityContext,
} from '../project/projectTypes'
import type {
  ApiScanResult,
  ApiScanSubmission,
  DependencyInventorySubmission,
  DependencyScanResult,
  SecretScanResult,
  SecretScanSubmission,
  SecurityEngineHealth,
  SecurityFinding,
} from '../security/securityTypes'
import type {
  SecurityAiHealth,
  SecurityAiSummaryRequest,
  SecurityChatRequest,
  SecurityChatResponse,
  SecurityFindingAiAnalysis,
  SecurityFindingsAiSummary,
  SecurityFixProposal,
  SecurityFixRequest,
} from '../ai/aiTypes'
import type { CiCheckResult, CiPolicyRequest, SecurityPosture } from '../posture/postureTypes'

// --------------------------------------------------------------------------
// Contrat avec le backend (miroir de app/code/schemas.py)
// --------------------------------------------------------------------------

export interface CodeLocation {
  line_start: number
  line_end: number
  column_start: number
  column_end: number
  snippet: string
}

export interface RiskFactor {
  name: string
  detail: string
  weight: number
}

export interface CodeFinding {
  finding_uid: string
  scan_uid: string
  rule_id: string
  category: string
  category_label: string
  cwe: string | null
  owasp: string | null
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  severity_label: string
  risk_score: number
  risk_band: string
  confidence: number
  source: 'rule' | 'ia'
  source_label: string
  title: string
  explanation: string
  why_dangerous: string
  potential_impact: string[]
  recommendations: string[]
  risk_factors: RiskFactor[]
  location: CodeLocation
  file_path: string
  fix_available: boolean
  fix_summary: string
  status: 'open' | 'dismissed' | 'fixed'
  status_label: string
  created_at: string
  /**
   * Moteur d'origine, pour les findings de **sécurité projet** seulement.
   *
   * Absent des findings produits par `/api/code/scan` : c'est précisément
   * cette absence qui permet au registre de remplacer les findings d'un
   * fichier analysé sans effacer le secret qui y a été repéré. Voir
   * `security/findingAdapter.ts`.
   */
  detection_engine?: string
}

export interface SeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
}

export interface CodeScanResult {
  scan_uid: string
  file_path: string
  language: string
  content_hash: string
  line_count: number
  rules_version: string
  analysis_status: string
  analysis_status_label: string
  analysis_error: string | null
  findings: CodeFinding[]
  findings_count: number
  counts: SeverityCounts
  cached: boolean
  ai_enrichment_requested: boolean
  ai_enrichment_applied: boolean
}

export interface CodeHealth {
  status: string
  analysis_enabled: boolean
  ai_enabled: boolean
  rules_version: string
  rules_count: number
  api_version: string
  max_content_bytes: number
  database: string
  /**
   * Les routes sensibles exigent-elles un jeton ?
   *
   * Annonce par la seule route publique. Sans elle, un 401 et un backend
   * eteint donneraient le meme symptome — une extension muette.
   */
  auth_required: boolean
  /** Le backend sait-il tenir un contexte de projet (phase 1) ? */
  project_context_enabled: boolean
  /**
   * Le backend porte-t-il le moteur de sécurité projet (phase 2) ?
   *
   * Permet à l'extension de se taire proprement face à un backend plus
   * ancien plutôt que d'enchaîner les 404 après un parcours complet du
   * disque.
   */
  project_security_enabled: boolean
}

/** Correctif proposé par le backend. Aucune écriture n'est faite côté serveur. */
export interface CodeFixProposal {
  finding_uid: string
  available: boolean
  original_line: string | null
  replacement_line: string | null
  explanation: string
  diff: string | null
  blockers: string[]
  manual_steps: string[]
  line: number | null
  file_path: string
  applies_automatically: boolean
}

export interface FindingDecision {
  status: 'dismissed' | 'fixed'
  reason?: string
  actor?: string
}

/** Filtres acceptés par `GET /api/code/findings`. */
export interface FindingsQuery {
  limit?: number
  offset?: number
  file_path?: string
  severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  status?: 'open' | 'dismissed' | 'fixed'
  category?: string
  /**
   * Restreint l'historique a un projet.
   *
   * Sans ce filtre, la route renvoie les findings de tous les projets
   * analyses par ce backend : deux projets partageant `src/app.py` se
   * melangeraient dans la vue.
   */
  project_uid?: string
  /**
   * Avec `project_uid` : seul le dernier scan de chaque fichier.
   *
   * Un dernier scan sans finding n'a aucune ligne dans l'historique ; sans
   * ce filtre, la reprise retiendrait le scan fautif précédent. Un backend
   * plus ancien ignore le paramètre.
   */
  current_only?: boolean
}

export interface ScanPayload {
  file_path: string
  language: string
  content: string
  content_hash: string
  workspace: string | null
  /**
   * Projet auquel appartient le fichier.
   *
   * Decide de deux choses cote backend : le filtrage des findings par
   * projet, et le cloisonnement du flux temps reel. `null` pour un fichier
   * ouvert hors de tout dossier — il reste analysable, sans contexte.
   */
  project_uid: string | null
  ai_enrichment: boolean
}

// --------------------------------------------------------------------------
// Erreurs
// --------------------------------------------------------------------------

/**
 * Erreur déjà traduite, prête à être affichée.
 *
 * Aucune trace d'exécution brute n'atteint l'utilisateur : le détail
 * technique reste dans `detail`, destiné au canal de sortie.
 */
export class BackendError extends Error {
  readonly status: number
  readonly detail: string | undefined

  constructor(message: string, status = 0, detail?: string) {
    super(message)
    this.name = 'BackendError'
    this.status = status
    this.detail = detail
  }
}

/** Analyse abandonnée parce qu'une plus récente l'a remplacée. */
export class ScanCancelledError extends Error {
  constructor() {
    super(FR.errors.cancelled)
    this.name = 'ScanCancelledError'
  }
}

/** Traduit un code HTTP en message compréhensible. */
function messageForStatus(status: number): string {
  switch (status) {
    case 400:
      return FR.errors.badRequest
    case 401:
      // Message dedie : « erreur inattendue » laisserait l'utilisateur sans
      // piste alors que la cause et le remede sont connus.
      return FR.backendUrl.unauthorized
    case 404:
      return FR.errors.notFound
    case 408:
      return FR.errors.timeout
    case 422:
      return FR.errors.invalidContent
    case 500:
      return FR.errors.serverError
    case 502:
      return FR.errors.badGateway
    case 503:
      return FR.errors.unavailable
    default:
      return FR.errors.unexpected
  }
}

/**
 * Extrait le message du corps d'erreur FastAPI.
 *
 * Le backend renvoie `{"detail": {"error": "...", "detail": "..."}}` pour
 * ses erreurs métier, et une liste pour les erreurs de validation.
 */
function extractDetail(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') {
    return undefined
  }

  const detail = (body as { detail?: unknown }).detail

  if (typeof detail === 'string') {
    return detail
  }

  if (Array.isArray(detail)) {
    const first = detail[0] as { msg?: unknown } | undefined
    if (first && typeof first.msg === 'string') {
      return first.msg.replace(/^Value error,\s*/, '')
    }
    return undefined
  }

  if (detail && typeof detail === 'object') {
    const structured = detail as { error?: unknown; detail?: unknown }
    const parts = [structured.error, structured.detail].filter(
      (part): part is string => typeof part === 'string' && part.length > 0
    )
    return parts.length > 0 ? parts.join(' — ') : undefined
  }

  return undefined
}

// --------------------------------------------------------------------------
// Client
// --------------------------------------------------------------------------

export interface BackendClientOptions {
  /** Adresse du backend, sans slash final. */
  baseUrl: string
  /** Délai maximal d'une requête, en millisecondes. */
  timeoutMs?: number
  /**
   * Trace de diagnostic : méthode, URL, code HTTP, durée.
   *
   * Jamais le corps des requêtes ni celui des réponses — le contenu des
   * fichiers analysés ne doit apparaître dans aucun journal. L'appelant
   * décide de la destination (canal de sortie, rien du tout).
   */
  onTrace?: (message: string) => void
  /**
   * En-tete d'authentification a joindre a chaque requete.
   *
   * Fourni par l'appelant, jamais lu ici : ce module ne connait pas
   * l'emplacement du jeton et n'a aucun moyen de le journaliser par
   * accident. `undefined` signifie « aucun jeton disponible » — la requete
   * part quand meme, et le 401 qui suit porte un message explicite.
   */
  authHeader?: () => Promise<Record<string, string> | undefined>
  /**
   * Appele sur un 401, une seule fois par requete.
   *
   * Permet de relire le jeton : le backend a pu redemarrer avec une
   * nouvelle valeur, auquel cas le fichier est a jour et la reserve est
   * perimee. Retourner `true` demande une seule nouvelle tentative.
   */
  onUnauthorized?: () => Promise<boolean>
}

const DEFAULT_TIMEOUT_MS = 20_000

/**
 * Relaie l'annulation d'un signal externe vers le controleur interne.
 *
 * Retourne la fonction de detachement, a appeler dans un `finally` pour
 * ne laisser aucun ecouteur derriere soi.
 */
function linkAbort(
  external: AbortSignal | undefined,
  target: AbortController
): () => void {
  if (!external) {
    return () => undefined
  }

  if (external.aborted) {
    target.abort()
    return () => undefined
  }

  const forward = () => target.abort()
  external.addEventListener('abort', forward, { once: true })
  return () => external.removeEventListener('abort', forward)
}


export class BackendClient {
  private baseUrl: string
  private timeoutMs: number
  private readonly onTrace: ((message: string) => void) | undefined
  private readonly authHeader:
    | (() => Promise<Record<string, string> | undefined>)
    | undefined
  private readonly onUnauthorized: (() => Promise<boolean>) | undefined

  constructor(options: BackendClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '')
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.onTrace = options.onTrace
    this.authHeader = options.authHeader
    this.onUnauthorized = options.onUnauthorized
  }

  private trace(message: string): void {
    this.onTrace?.(message)
  }

  /** Met à jour l'adresse quand l'utilisateur change le réglage. */
  setBaseUrl(baseUrl: string): void {
    this.baseUrl = baseUrl.replace(/\/+$/, '')
  }

  get url(): string {
    return this.baseUrl
  }

  /** État du service d'analyse. */
  async health(signal?: AbortSignal): Promise<CodeHealth> {
    return this.request<CodeHealth>('/api/code/health', { method: 'GET' }, signal)
  }

  /**
   * Analyse un document.
   *
   * Un seul document est transmis par appel : jamais le workspace entier.
   */
  async scan(payload: ScanPayload, signal?: AbortSignal): Promise<CodeScanResult> {
    return this.request<CodeScanResult>(
      '/api/code/scan',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      },
      signal
    )
  }

  /**
   * Relit une analyse déjà enregistrée.
   *
   * **Repli du flux temps réel.** Quand l'enrichissement IA est annoncé
   * en cours et que l'événement SSE de fin n'arrive pas — flux coupé,
   * événement perdu, backend redémarré — cette route donne l'état final
   * sans rejouer l'analyse. Le contenu du fichier n'est pas retransmis :
   * le backend répond depuis ce qu'il a déjà en base.
   */
  async getScan(scanUid: string, signal?: AbortSignal): Promise<CodeScanResult> {
    return this.request<CodeScanResult>(
      `/api/code/scans/${encodeURIComponent(scanUid)}`,
      { method: 'GET' },
      signal
    )
  }

  /**
   * Historique des findings déjà enregistrés par le backend.
   *
   * Sert au rafraîchissement de la vue « Security » : après un
   * redémarrage de l'éditeur, les résultats des analyses précédentes sont
   * repris d'ici plutôt que ré-analysés. Aucun contenu de fichier n'est
   * transmis dans un sens ni dans l'autre.
   */
  async listFindings(
    query: FindingsQuery = {},
    signal?: AbortSignal
  ): Promise<CodeFinding[]> {
    const parameters = new URLSearchParams()
    if (query.limit !== undefined) {
      parameters.set('limit', String(query.limit))
    }
    if (query.offset !== undefined) {
      parameters.set('offset', String(query.offset))
    }
    if (query.file_path) {
      parameters.set('file_path', query.file_path)
    }
    if (query.severity) {
      parameters.set('severity', query.severity)
    }
    if (query.status) {
      parameters.set('status', query.status)
    }
    if (query.category) {
      parameters.set('category', query.category)
    }
    if (query.project_uid) {
      parameters.set('project_uid', query.project_uid)
    }
    if (query.current_only) {
      parameters.set('current_only', 'true')
    }

    const suffix = parameters.toString()
    const body = await this.request<unknown>(
      `/api/code/findings${suffix ? `?${suffix}` : ''}`,
      { method: 'GET' },
      signal
    )

    // La route renvoie une liste ; un objet signalerait un backend d'une
    // autre version, qu'on préfère ignorer plutôt qu'afficher de travers.
    return Array.isArray(body) ? (body as CodeFinding[]) : []
  }

  /**
   * Demande un correctif pour un finding.
   *
   * `currentLine` permet au backend de refuser si la ligne a changé depuis
   * l'analyse. Le serveur ne modifie jamais le fichier : il décrit la
   * modification, l'éditeur l'applique après confirmation.
   */
  async proposeFix(
    findingUid: string,
    currentLine?: string,
    signal?: AbortSignal
  ): Promise<CodeFixProposal> {
    const query =
      currentLine === undefined
        ? ''
        : `?current_line=${encodeURIComponent(currentLine)}`

    return this.request<CodeFixProposal>(
      `/api/code/findings/${encodeURIComponent(findingUid)}/fix${query}`,
      { method: 'POST' },
      signal
    )
  }

  /** Enregistre la décision du développeur : ignoré (faux positif) ou corrigé. */
  async decideFinding(
    findingUid: string,
    decision: FindingDecision,
    signal?: AbortSignal
  ): Promise<CodeFinding> {
    return this.request<CodeFinding>(
      `/api/code/findings/${encodeURIComponent(findingUid)}/decision`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(decision),
      },
      signal
    )
  }

  // ---------------- Contexte de projet (phase 1) ----------------

  /**
   * Enregistre le projet et obtient son identifiant stable.
   *
   * Idempotent côté backend : deux appels pour la même racine renvoient le
   * même `project_uid`. Ce qui part ici est **l'empreinte** du chemin
   * racine, jamais le chemin : il révélerait le nom de l'utilisateur et
   * l'arborescence de son poste.
   */
  async discoverProject(
    submission: ProjectDiscoverSubmission,
    signal?: AbortSignal
  ): Promise<ProjectRegistration> {
    return this.request<ProjectRegistration>(
      '/api/project/discover',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(submission),
      },
      signal
    )
  }

  /**
   * Soumet l'index du projet et reçoit le contexte recalculé.
   *
   * L'index ne porte que des **métadonnées** : chemin relatif, taille,
   * empreinte, date. Aucun contenu de fichier ne franchit cette frontière,
   * et les manifestes n'y sont représentés que par des noms de dépendances.
   */
  async submitProjectIndex(
    projectUid: string,
    submission: ProjectIndexSubmission,
    signal?: AbortSignal
  ): Promise<ProjectSecurityContext> {
    return this.request<ProjectSecurityContext>(
      `/api/project/${encodeURIComponent(projectUid)}/index`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(submission),
      },
      signal
    )
  }

  /**
   * Relit le contexte déjà enregistré, sans nouveau parcours.
   *
   * Sert au démarrage d'un projet déjà connu : afficher le contexte de la
   * session précédente vaut mieux qu'une vue vide pendant qu'une découverte
   * tourne. Un 404 est une réponse normale — projet jamais indexé.
   */
  async getProjectContext(
    projectUid: string,
    signal?: AbortSignal
  ): Promise<ProjectSecurityContext> {
    return this.request<ProjectSecurityContext>(
      `/api/project/${encodeURIComponent(projectUid)}/context`,
      { method: 'GET' },
      signal
    )
  }

  // ---------------- Sécurité projet (phase 2) ----------------

  /**
   * Capacités du moteur de sécurité projet.
   *
   * Consultée **avant** de balayer : lancer un parcours complet du disque
   * pour découvrir ensuite que la route refuse serait du travail perdu.
   */
  async securityHealth(signal?: AbortSignal): Promise<SecurityEngineHealth> {
    return this.request<SecurityEngineHealth>(
      '/api/security/health',
      { method: 'GET' },
      signal
    )
  }

  /**
   * Soumet un balayage de secrets réalisé **sur le poste**.
   *
   * Ce qui part ici : un chemin relatif, une ligne, un type de secret, une
   * confiance, et une preuve **déjà expurgée**. Jamais la valeur détectée,
   * jamais le contenu du fichier. Le backend ré-expurge à la réception :
   * la garantie ne repose pas sur ce seul appel.
   */
  async submitSecretScan(
    projectUid: string,
    submission: SecretScanSubmission,
    signal?: AbortSignal
  ): Promise<SecretScanResult> {
    return this.request<SecretScanResult>(
      `/api/project/${encodeURIComponent(projectUid)}/secrets`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(submission),
      },
      signal
    )
  }

  /**
   * Soumet l'analyse de sécurité d'API réalisée sur le poste.
   *
   * Ce qui part : un chemin relatif, une ligne, un type de problème et un
   * extrait de **déclaration** déjà expurgé. Jamais le contenu du
   * fichier, jamais le corps d'un gestionnaire de route — la détection a
   * tourné en local, et c'est son constat qui traverse, pas sa matière.
   */
  async submitApiScan(
    projectUid: string,
    submission: ApiScanSubmission,
    signal?: AbortSignal
  ): Promise<ApiScanResult> {
    return this.request<ApiScanResult>(
      `/api/project/${encodeURIComponent(projectUid)}/api-security`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(submission),
      },
      signal
    )
  }

  /**
   * Soumet l'inventaire des dépendances lu dans les manifestes.
   *
   * L'extension n'installe rien et n'exécute aucun gestionnaire de
   * paquets : elle lit des fichiers texte. L'interrogation de la base de
   * vulnérabilités est faite par le backend, seul détenteur de la sortie
   * réseau.
   */
  async submitDependencyInventory(
    projectUid: string,
    submission: DependencyInventorySubmission,
    signal?: AbortSignal
  ): Promise<DependencyScanResult> {
    return this.request<DependencyScanResult>(
      `/api/project/${encodeURIComponent(projectUid)}/dependencies`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(submission),
      },
      signal
    )
  }

  /**
   * Relit les findings de sécurité d'un projet, sans nouveau balayage.
   *
   * Sert au démarrage : afficher ce qu'on savait de la session précédente
   * vaut mieux qu'une vue vide pendant qu'un balayage tourne.
   */
  async listProjectFindings(
    projectUid: string,
    query: { category?: string; status?: string; limit?: number } = {},
    signal?: AbortSignal
  ): Promise<SecurityFinding[]> {
    const parameters = new URLSearchParams()
    if (query.category) {
      parameters.set('category', query.category)
    }
    if (query.status) {
      parameters.set('status', query.status)
    }
    if (query.limit !== undefined) {
      parameters.set('limit', String(query.limit))
    }

    const suffix = parameters.toString()
    const body = await this.request<unknown>(
      `/api/project/${encodeURIComponent(projectUid)}/findings${
        suffix ? `?${suffix}` : ''
      }`,
      { method: 'GET' },
      signal
    )

    // La route renvoie une liste ; un objet signalerait un backend d'une
    // autre version, qu'on préfère ignorer plutôt qu'afficher de travers.
    return Array.isArray(body) ? (body as SecurityFinding[]) : []
  }

  // ---------------- Assistant IA de sécurité (phase 6) ----------------
  //
  // L'extension n'appelle aucun modèle : ces routes passent par le
  // backend, seul détenteur de la clé. Ce qui part d'ici tient en un
  // identifiant de finding, ou une question déjà expurgée — jamais le
  // contenu d'un fichier.
  //
  // Un 503 est une réponse **normale** : l'assistant est optionnel, et la
  // détection continue sans lui.

  /** État de l'assistant. Consulté avant d'afficher un bouton IA. */
  async securityAiHealth(signal?: AbortSignal): Promise<SecurityAiHealth> {
    return this.request<SecurityAiHealth>(
      '/api/security/ai/health',
      { method: 'GET' },
      signal
    )
  }

  /**
   * Fait expliquer un finding **existant**.
   *
   * Aucun corps : le backend relit le finding depuis sa base, déjà
   * expurgé. `force` ignore l'explication en cache.
   */
  async analyzeFindingWithAi(
    projectUid: string,
    findingId: string,
    options: { force?: boolean } = {},
    signal?: AbortSignal
  ): Promise<SecurityFindingAiAnalysis> {
    const query = options.force ? '?force=true' : ''
    return this.request<SecurityFindingAiAnalysis>(
      `/api/project/${encodeURIComponent(projectUid)}/findings/${encodeURIComponent(
        findingId
      )}/ai-analysis${query}`,
      { method: 'POST' },
      signal
    )
  }

  /** Résume plusieurs findings du projet et en donne les relations. */
  async summarizeFindingsWithAi(
    projectUid: string,
    request: SecurityAiSummaryRequest,
    signal?: AbortSignal
  ): Promise<SecurityFindingsAiSummary> {
    return this.request<SecurityFindingsAiSummary>(
      `/api/project/${encodeURIComponent(projectUid)}/ai/summary`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      },
      signal
    )
  }

  /**
   * Pose une question sur la sécurité du projet.
   *
   * La question doit **déjà** avoir traversé `redactFreeText` : ce
   * module n'expurge rien lui-même, et le backend expurge une seconde
   * fois.
   */
  async askSecurityChat(
    projectUid: string,
    request: SecurityChatRequest,
    signal?: AbortSignal
  ): Promise<SecurityChatResponse> {
    return this.request<SecurityChatResponse>(
      `/api/project/${encodeURIComponent(projectUid)}/ai/chat`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      },
      signal
    )
  }

  // ---------------- Remédiation assistée (phase 7) ----------------

  /**
   * Demande un correctif borné pour un finding existant.
   *
   * Le backend **n'écrit rien** : il décrit une modification. Ce qui part
   * d'ici est un extrait borné et déjà expurgé, avec l'empreinte du
   * fichier entier — jamais le fichier. C'est l'éditeur qui appliquera,
   * après confirmation explicite, et les moteurs déterministes qui diront
   * ensuite si le problème a disparu.
   */
  async proposeFixWithAi(
    projectUid: string,
    findingId: string,
    request: SecurityFixRequest,
    signal?: AbortSignal
  ): Promise<SecurityFixProposal> {
    return this.request<SecurityFixProposal>(
      `/api/project/${encodeURIComponent(projectUid)}/findings/${encodeURIComponent(
        findingId
      )}/ai-fix`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
      },
      signal
    )
  }

  // ---------------- Posture et CI/CD (phase 8) ----------------

  /**
   * Posture de sécurité explicable du projet. Lecture seule : aucun
   * balayage n'est lancé, aucune IA consultée.
   */
  async getPosture(projectUid: string, signal?: AbortSignal): Promise<SecurityPosture> {
    return this.request<SecurityPosture>(
      `/api/project/${encodeURIComponent(projectUid)}/posture`,
      { method: 'GET' },
      signal
    )
  }

  /**
   * Contrôle CI/CD déterministe. Un champ de politique absent reprend la
   * configuration du backend.
   */
  async ciCheck(
    projectUid: string,
    policy: CiPolicyRequest = {},
    signal?: AbortSignal
  ): Promise<CiCheckResult> {
    return this.request<CiCheckResult>(
      `/api/project/${encodeURIComponent(projectUid)}/ci-check`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(policy),
      },
      signal
    )
  }

  // ---------------- Interne ----------------

  /**
   * Requête authentifiée, avec une seule reprise sur 401.
   *
   * La reprise couvre un cas concret : le backend redémarre et génère un
   * nouveau jeton. L'extension détient alors une valeur périmée, et sans
   * reprise elle resterait muette jusqu'au redémarrage de l'éditeur. Une
   * seule tentative : si le jeton relu est refusé lui aussi, insister ne
   * ferait qu'accumuler des refus dans les journaux du backend.
   */
  private async request<T>(
    path: string,
    init: RequestInit,
    externalSignal?: AbortSignal
  ): Promise<T> {
    try {
      return await this.send<T>(path, init, externalSignal)
    } catch (error) {
      const refused = error instanceof BackendError && error.status === 401
      if (!refused || this.onUnauthorized === undefined) {
        throw error
      }

      // Le jeton est relu, jamais journalisé : la trace dit qu'on réessaie,
      // pas avec quoi.
      this.trace(`↻ ${init.method ?? 'GET'} ${path} — jeton relu après 401`)
      const retry = await this.onUnauthorized()
      if (!retry) {
        throw error
      }
      return this.send<T>(path, init, externalSignal)
    }
  }

  private async send<T>(
    path: string,
    init: RequestInit,
    externalSignal?: AbortSignal
  ): Promise<T> {
    // Deux raisons d'abandonner : le délai est dépassé, ou l'appelant a
    // annulé (nouveau contenu). Les deux doivent être distinguées.
    const timeoutController = new AbortController()
    const timer = setTimeout(() => timeoutController.abort(), this.timeoutMs)

    // `AbortSignal.any` n'existe qu'a partir de Node 20 ; VS Code 1.85
    // embarque Node 18. On relaie donc l'annulation a la main.
    const unlink = linkAbort(externalSignal, timeoutController)

    const url = `${this.baseUrl}${path}`
    const method = init.method ?? 'GET'
    const started = Date.now()
    this.trace(`→ ${method} ${url}`)

    // Résolu à chaque envoi plutôt qu'une fois pour toutes : après un 401,
    // la valeur a pu changer entre les deux tentatives.
    const authorization = this.authHeader ? await this.authHeader() : undefined

    let response: Response
    try {
      response = await fetch(url, {
        ...init,
        headers: { ...(init.headers as Record<string, string>), ...authorization },
        signal: timeoutController.signal,
      })
    } catch (cause) {
      this.trace(
        `✗ ${method} ${url} — aucune réponse après ${Date.now() - started} ms : ` +
          `${cause instanceof Error ? cause.message : String(cause)}`
      )
      if (externalSignal?.aborted) {
        throw new ScanCancelledError()
      }
      if (timeoutController.signal.aborted) {
        throw new BackendError(FR.errors.timeout, 408)
      }
      throw new BackendError(
        FR.errors.unreachable,
        0,
        cause instanceof Error ? cause.message : String(cause)
      )
    } finally {
      clearTimeout(timer)
      unlink()
    }

    this.trace(`← HTTP ${response.status} ${method} ${url} (${Date.now() - started} ms)`)

    // Le corps est lu une seule fois, quel que soit le code.
    let body: unknown
    let raw = ''
    try {
      raw = await response.text()
      body = raw.length > 0 ? JSON.parse(raw) : null
    } catch {
      if (!response.ok) {
        throw new BackendError(messageForStatus(response.status), response.status)
      }
      throw new BackendError(FR.errors.invalidJson, response.status, raw.slice(0, 200))
    }

    if (!response.ok) {
      throw new BackendError(
        messageForStatus(response.status),
        response.status,
        extractDetail(body)
      )
    }

    if (body === null || typeof body !== 'object') {
      throw new BackendError(FR.errors.invalidJson, response.status)
    }

    return body as T
  }
}
