/**
 * Assistant IA de sécurité côté extension : état et orchestration (phase 6).
 *
 * Ce module décide de ce que la fenêtre de l'assistant affiche, et de ce
 * qui part vers le backend. Il ne connaît ni `vscode` ni le DOM : la
 * fenêtre (`ui/aiPanel.ts`) ne fait que rendre le modèle et relayer les
 * clics. Tout ce qui compte se vérifie donc en Node pur.
 *
 * Ce que ce module ne fait jamais
 * -------------------------------
 *
 * - **toucher un finding.** Il ne reçoit pas le registre des findings :
 *   il n'a aucun moyen d'en créer, d'en retirer ou d'en requalifier un.
 *   La gravité affichée est `deterministic_severity`, recopiée par le
 *   backend depuis le moteur ;
 * - **envoyer du code.** Ce qui part : un identifiant de finding, ou une
 *   question expurgée par `redactFreeText` avant l'envoi ;
 * - **appeler un modèle.** Tout passe par le backend, seul détenteur de la
 *   clé.
 *
 * Une indisponibilité n'est pas une panne
 * ---------------------------------------
 *
 * Un 503 du backend se lit « l'assistant n'est pas là » : l'état
 * `unavailable` l'affiche avec la raison rédigée par le backend, et
 * rappelle que la détection continue sans lui. Une réponse illisible, elle,
 * est une erreur — jamais une fiche vide, qui se lirait « rien à signaler ».
 */

import { BackendError } from '../api/backendClient'
import { FR } from '../i18n/fr'
import { MAX_QUESTION_LENGTH, MAX_TURN_LENGTH, redactFreeText } from './aiRedaction'
import type {
  SecurityAiHealth,
  SecurityAiSummaryRequest,
  SecurityChatRequest,
  SecurityChatResponse,
  SecurityChatTurn,
  SecurityFindingAiAnalysis,
  SecurityFindingsAiSummary,
  SecurityFixProposal,
} from './aiTypes'

/** Tours d'historique renvoyés au backend, qui applique aussi sa borne. */
export const MAX_HISTORY_TURNS = 6

/** Questions conservées à l'écran. Au-delà, les plus anciennes sortent. */
export const MAX_CHAT_ENTRIES = 20

// --------------------------------------------------------------------------
// Modèle affiché
// --------------------------------------------------------------------------

export type AiView =
  | { kind: 'analysis'; findingId: string; findingTitle: string }
  | { kind: 'summary' }
  | { kind: 'chat' }
  /** Phase 7 : correctif proposé pour un finding. */
  | { kind: 'fix'; findingId: string; findingTitle: string }

export type AiStatus = 'idle' | 'loading' | 'ready' | 'unavailable' | 'error'

/**
 * Étapes d'un correctif assisté (phase 7), telles qu'affichées.
 *
 *     loading → proposed → applying → rescanning → done
 *             ↘ refused    (pas de correctif automatique sûr)
 *             ↘ rejected   (proposition dangereuse ou illisible)
 *     proposed → cancelled | stale (fichier modifié) | failed (retour arrière)
 *
 * Seule l'étape `proposed` affiche le bouton « Appliquer ».
 */
export type FixStage =
  | 'loading'
  | 'proposed'
  | 'refused'
  | 'rejected'
  | 'applying'
  | 'rescanning'
  | 'done'
  | 'cancelled'
  | 'stale'
  | 'failed'

export interface FixPanelState {
  stage: FixStage
  /** Proposition **validée** côté extension. Absente tant qu'elle ne l'est pas. */
  proposal?: SecurityFixProposal
  /** Lignes actuelles de la plage, expurgées : jamais un secret à l'écran. */
  currentLines?: string[]
  /** Refus, rejet ou échec, prêt à afficher. */
  message?: string
  /** Remédiation manuelle, quand il n'y a pas de correctif automatique. */
  manualSteps?: string[]
  explanation?: string
  /** Verdict des moteurs après application — jamais celui de l'IA. */
  verification?: 'resolved' | 'still_present' | 'unverified'
  restored?: boolean
}

export interface ChatEntry {
  /** Question telle qu'elle est partie — ou telle que le backend l'a expurgée. */
  question: string
  /** Vrai quand l'extension a masqué quelque chose avant l'envoi. */
  redacted: boolean
  pending: boolean
  response?: SecurityChatResponse
  error?: string
}

export interface AiPanelModel {
  view: AiView
  status: AiStatus
  /** Raison d'indisponibilité ou message d'erreur, prêt à afficher. */
  message: string
  analysis?: SecurityFindingAiAnalysis
  summary?: SecurityFindingsAiSummary
  chat: ChatEntry[]
  chatAvailable: boolean
  /** Mise en garde rédigée par le backend. */
  disclaimer: string
  /** Phase 7 : état du correctif assisté en cours. */
  fix?: FixPanelState
}

export function initialModel(view: AiView = { kind: 'chat' }): AiPanelModel {
  return {
    view,
    status: 'idle',
    message: '',
    chat: [],
    chatAvailable: false,
    disclaimer: '',
  }
}

// --------------------------------------------------------------------------
// Validation des réponses
// --------------------------------------------------------------------------
//
// Le backend valide déjà la sortie du modèle. Ce contrôle-ci protège
// l'affichage d'un backend d'une autre version ou d'une réponse tronquée :
// une fiche remplie de `undefined` serait pire qu'un message d'erreur.

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0
}

export function isAnalysis(value: unknown): value is SecurityFindingAiAnalysis {
  return (
    isObject(value) &&
    value.ai_generated === true &&
    nonEmptyString(value.finding_id) &&
    nonEmptyString(value.explanation) &&
    typeof value.deterministic_severity === 'string'
  )
}

export function isSummary(value: unknown): value is SecurityFindingsAiSummary {
  return isObject(value) && value.ai_generated === true && nonEmptyString(value.summary)
}

export function isChatResponse(value: unknown): value is SecurityChatResponse {
  return isObject(value) && value.ai_generated === true && nonEmptyString(value.answer)
}

/** Erreur d'une réponse reçue mais inexploitable. */
export class MalformedAiResponseError extends Error {
  constructor() {
    super(FR.assistant.errorFor(502))
    this.name = 'MalformedAiResponseError'
  }
}

// --------------------------------------------------------------------------
// Erreurs → état affiché
// --------------------------------------------------------------------------

/**
 * Traduit une erreur en état de la fenêtre.
 *
 * 503 → `unavailable`, avec la raison du backend : c'est l'assistant qui
 * manque, pas l'analyse de sécurité. Tout le reste → `error`, avec un
 * message qui dit ce qui s'est passé sans jamais suggérer que le finding
 * aurait disparu ou changé.
 */
export function failureState(error: unknown): { status: AiStatus; message: string } {
  if (error instanceof BackendError) {
    if (error.status === 503) {
      return {
        status: 'unavailable',
        message: error.detail || FR.assistant.unavailableDefault,
      }
    }
    const base = FR.assistant.errorFor(error.status)
    return {
      status: 'error',
      message: error.detail ? `${base} (${error.detail})` : base,
    }
  }
  if (error instanceof MalformedAiResponseError) {
    return { status: 'error', message: error.message }
  }
  return { status: 'error', message: FR.assistant.errorFor(0) }
}

// --------------------------------------------------------------------------
// Messages venus de la fenêtre
// --------------------------------------------------------------------------

export type PanelMessage =
  | { action: 'ask'; question: string }
  | { action: 'reanalyze' }
  | { action: 'summarize' }
  /**
   * Phase 7. Aucune de ces trois actions n'écrit : « applyFix » ouvre la
   * fenêtre de confirmation **native** de l'éditeur, qu'une page ne peut
   * pas valider à la place de l'utilisateur.
   */
  | { action: 'applyFix' }
  | { action: 'cancelFix' }
  | { action: 'showFixDiff' }

/**
 * Valide un message de la webview.
 *
 * La webview est une page : rien de ce qu'elle poste n'est cru sur
 * parole. Seules les actions listées existent, la question est une chaîne
 * bornée, et tout le reste est ignoré sans être journalisé.
 */
export function parsePanelMessage(raw: unknown): PanelMessage | undefined {
  if (!isObject(raw)) {
    return undefined
  }
  switch (raw.action) {
    case 'ask': {
      if (typeof raw.question !== 'string') {
        return undefined
      }
      const question = raw.question.trim()
      if (question.length === 0) {
        return undefined
      }
      return { action: 'ask', question: question.slice(0, MAX_QUESTION_LENGTH) }
    }
    case 'reanalyze':
      return { action: 'reanalyze' }
    case 'summarize':
      return { action: 'summarize' }
    case 'applyFix':
    case 'cancelFix':
    case 'showFixDiff':
      return { action: raw.action }
    default:
      return undefined
  }
}

// --------------------------------------------------------------------------
// Chat
// --------------------------------------------------------------------------

/** Question prête à partir, et l'indication qu'elle a été modifiée. */
export function prepareQuestion(raw: string): { question: string; redacted: boolean } {
  const trimmed = (raw ?? '').trim().slice(0, MAX_QUESTION_LENGTH)
  const question = redactFreeText(trimmed)
  return { question, redacted: question !== trimmed }
}

/**
 * Historique renvoyé avec la question suivante.
 *
 * Seuls les échanges **aboutis** comptent : une question restée sans
 * réponse, ou en erreur, n'apprend rien au modèle. Les réponses sont
 * reprises telles que le backend les a rendues, et repassent quand même
 * par l'expurgation — une réponse de modèle peut citer une preuve.
 */
export function chatHistory(
  entries: readonly ChatEntry[],
  maxTurns = MAX_HISTORY_TURNS
): SecurityChatTurn[] {
  const turns: SecurityChatTurn[] = []
  for (const entry of entries) {
    if (entry.pending || !entry.response) {
      continue
    }
    turns.push({ role: 'user', message: redactFreeText(entry.question, MAX_TURN_LENGTH) })
    turns.push({
      role: 'assistant',
      message: redactFreeText(entry.response.answer, MAX_TURN_LENGTH),
    })
  }
  return maxTurns <= 0 ? [] : turns.slice(-maxTurns)
}

// --------------------------------------------------------------------------
// Orchestration
// --------------------------------------------------------------------------

/** Ce dont le contrôleur a besoin du client HTTP. Rien d'autre. */
export interface SecurityAiBackend {
  securityAiHealth(): Promise<SecurityAiHealth>
  analyzeFindingWithAi(
    projectUid: string,
    findingId: string,
    options?: { force?: boolean }
  ): Promise<SecurityFindingAiAnalysis>
  summarizeFindingsWithAi(
    projectUid: string,
    request: SecurityAiSummaryRequest
  ): Promise<SecurityFindingsAiSummary>
  askSecurityChat(
    projectUid: string,
    request: SecurityChatRequest
  ): Promise<SecurityChatResponse>
}

export interface SecurityAiControllerOptions {
  backend: SecurityAiBackend
  /** Résolu à chaque appel : le projet change quand on ouvre un autre dossier. */
  projectUid: () => string | undefined
  /** Appelé à chaque changement du modèle. */
  onChange?: (model: AiPanelModel) => void
  log?: (message: string) => void
}

/**
 * Pilote une fenêtre de l'assistant.
 *
 * Une requête à la fois par type : relancer une analyse pendant qu'une
 * autre tourne remplace l'affichage, et la réponse de la plus ancienne est
 * écartée à son arrivée (`generation`). Sans cela, une réponse lente
 * pourrait écraser une réponse plus récente.
 */
export class SecurityAiController {
  private readonly backend: SecurityAiBackend
  private readonly projectUid: () => string | undefined
  private readonly onChange: ((model: AiPanelModel) => void) | undefined
  private readonly log: (message: string) => void
  private current: AiPanelModel = initialModel()
  private generation = 0

  constructor(options: SecurityAiControllerOptions) {
    this.backend = options.backend
    this.projectUid = options.projectUid
    this.onChange = options.onChange
    this.log = options.log ?? (() => undefined)
  }

  get model(): AiPanelModel {
    return this.current
  }

  /** Remplace l'état de disponibilité connu (issu de `/api/security/ai/health`). */
  applyHealth(health: SecurityAiHealth | undefined): void {
    this.update({
      chatAvailable: health?.chat_available === true,
      disclaimer: health?.disclaimer || this.current.disclaimer,
    })
    if (health && !health.available) {
      this.update({
        status: 'unavailable',
        message: health.reason || FR.assistant.unavailableDefault,
      })
    }
  }

  /** Relit l'état de l'assistant. Une panne vaut « indisponible ». */
  async refreshHealth(): Promise<SecurityAiHealth | undefined> {
    try {
      const health = await this.backend.securityAiHealth()
      this.applyHealth(health)
      return health
    } catch (error) {
      this.log(`état de l'assistant IA illisible : ${String(error)}`)
      this.update({ chatAvailable: false, ...failureState(error) })
      return undefined
    }
  }

  /** Explique un finding existant. */
  async analyze(findingId: string, findingTitle: string, force = false): Promise<void> {
    const projectUid = this.requireProject()
    if (!projectUid) {
      return
    }

    const ticket = ++this.generation
    this.update({
      view: { kind: 'analysis', findingId, findingTitle },
      status: 'loading',
      message: '',
      analysis: undefined,
      summary: undefined,
    })

    try {
      const body: unknown = await this.backend.analyzeFindingWithAi(projectUid, findingId, {
        force,
      })
      if (ticket !== this.generation) {
        return
      }
      if (!isAnalysis(body)) {
        throw new MalformedAiResponseError()
      }
      this.log(
        `explication IA reçue pour ${findingId}${body.cached ? ' (cache)' : ''} — ` +
          `gravité déterministe ${body.deterministic_severity} conservée`
      )
      this.update({
        status: 'ready',
        analysis: body,
        disclaimer: body.disclaimer || this.current.disclaimer,
      })
    } catch (error) {
      if (ticket !== this.generation) {
        return
      }
      this.fail(error)
    }
  }

  /** Relance l'analyse affichée, en ignorant le cache. */
  async reanalyze(): Promise<void> {
    const view = this.current.view
    if (view.kind === 'analysis') {
      await this.analyze(view.findingId, view.findingTitle, true)
    } else if (view.kind === 'summary') {
      await this.summarize()
    }
  }

  /** Résume les findings ouverts du projet. */
  async summarize(findingIds: string[] = []): Promise<void> {
    const projectUid = this.requireProject()
    if (!projectUid) {
      return
    }

    const ticket = ++this.generation
    this.update({
      view: { kind: 'summary' },
      status: 'loading',
      message: '',
      analysis: undefined,
      summary: undefined,
    })

    try {
      const body: unknown = await this.backend.summarizeFindingsWithAi(projectUid, {
        finding_ids: findingIds,
      })
      if (ticket !== this.generation) {
        return
      }
      if (!isSummary(body)) {
        throw new MalformedAiResponseError()
      }
      this.update({
        status: 'ready',
        summary: body,
        disclaimer: body.disclaimer || this.current.disclaimer,
      })
    } catch (error) {
      if (ticket !== this.generation) {
        return
      }
      this.fail(error)
    }
  }

  /**
   * Phase 7 : affiche l'état d'un correctif assisté.
   *
   * Le contrôleur ne pilote pas le correctif — c'est le déroulé côté
   * éditeur (`remediation/fixWorkflow.ts`) qui lit le fichier, applique
   * et relance l'analyse. Il ne fait que tenir ce qui est affiché, et
   * n'a toujours aucun accès aux findings.
   */
  showFix(findingId: string, findingTitle: string, state: FixPanelState): void {
    // Une analyse ou un résumé en vol ne doit pas écraser le correctif.
    this.generation += 1
    this.update({
      view: { kind: 'fix', findingId, findingTitle },
      status: 'ready',
      message: '',
      analysis: undefined,
      summary: undefined,
      fix: state,
    })
  }

  /** Met à jour l'étape du correctif affiché. Sans effet hors de la vue. */
  updateFix(findingId: string, patch: Partial<FixPanelState>): void {
    const view = this.current.view
    if (view.kind !== 'fix' || view.findingId !== findingId || !this.current.fix) {
      return
    }
    this.update({ fix: { ...this.current.fix, ...patch } })
  }

  /** Ouvre la vue chat sans rien envoyer. */
  showChat(): void {
    if (this.current.view.kind !== 'chat') {
      this.update({ view: { kind: 'chat' } })
    }
  }

  /**
   * Pose une question.
   *
   * La question est expurgée **avant** l'envoi ; l'entrée affichée est
   * ensuite remplacée par la version renvoyée par le backend, qui a pu
   * masquer davantage. L'utilisateur voit ainsi ce qui est réellement
   * parti.
   */
  async ask(rawQuestion: string): Promise<void> {
    const projectUid = this.requireProject()
    if (!projectUid) {
      return
    }

    const { question, redacted } = prepareQuestion(rawQuestion)
    if (!question) {
      return
    }

    const history = chatHistory(this.current.chat)
    const view = this.current.view
    const findingId =
      view.kind === 'analysis' || view.kind === 'fix' ? view.findingId : undefined

    const entry: ChatEntry = { question, redacted, pending: true }
    this.update({ chat: [...this.current.chat, entry].slice(-MAX_CHAT_ENTRIES) })

    try {
      const body: unknown = await this.backend.askSecurityChat(projectUid, {
        question,
        history,
        finding_id: findingId ?? null,
      })
      if (!isChatResponse(body)) {
        throw new MalformedAiResponseError()
      }
      this.replaceEntry(entry, {
        ...entry,
        pending: false,
        question: body.question || question,
        redacted: redacted || (body.question !== '' && body.question !== question),
        response: body,
      })
      if (body.disclaimer) {
        this.update({ disclaimer: body.disclaimer })
      }
    } catch (error) {
      const failure = failureState(error)
      this.replaceEntry(entry, { ...entry, pending: false, error: failure.message })
      if (failure.status === 'unavailable') {
        this.update({ chatAvailable: false })
      }
    }
  }

  // ---------------- Interne ----------------

  private requireProject(): string | undefined {
    const projectUid = this.projectUid()
    if (!projectUid) {
      this.update({ status: 'error', message: FR.assistant.noProject })
    }
    return projectUid
  }

  private fail(error: unknown): void {
    const failure = failureState(error)
    this.log(`assistant IA : ${failure.status} — ${failure.message}`)
    this.update(failure)
  }

  private replaceEntry(previous: ChatEntry, next: ChatEntry): void {
    this.update({
      chat: this.current.chat.map((item) => (item === previous ? next : item)),
    })
  }

  private update(patch: Partial<AiPanelModel>): void {
    this.current = { ...this.current, ...patch }
    this.onChange?.(this.current)
  }
}
