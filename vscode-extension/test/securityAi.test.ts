/**
 * Tests de l'assistant IA de sécurité côté extension (phase 6).
 *
 * Aucun appel réseau, aucun modèle : `fetch` est bouchonné pour le client,
 * et le contrôleur reçoit un faux backend qui enregistre ce qu'on lui
 * demande. Ce que ces tests verrouillent :
 *
 *     CE QUI PART     un identifiant de finding, ou une question déjà
 *                     expurgée. Jamais le contenu d'un fichier.
 *     GRAVITÉ         la seule gravité affichée est celle du moteur ; un
 *                     champ de gravité glissé dans une réponse est ignoré.
 *     FINDINGS        l'assistant ne touche pas au registre des findings.
 *     MARQUAGE        tout texte d'IA porte la pastille et la mise en garde.
 *     INDISPONIBLE    un 503 se lit « assistant absent », jamais « rien à
 *                     signaler » ; une réponse illisible est une erreur.
 *     CLOISONNEMENT   chaque appel vise le projet ouvert au moment de
 *                     l'appel.
 */

import assert from 'node:assert/strict'
import { afterEach, describe, it } from 'node:test'

import { BackendClient, BackendError, type CodeFinding } from '../src/api/backendClient'
import { MAX_QUESTION_LENGTH, redactFreeText } from '../src/ai/aiRedaction'
import type {
  SecurityAiHealth,
  SecurityChatRequest,
  SecurityChatResponse,
  SecurityFindingAiAnalysis,
  SecurityFindingsAiSummary,
} from '../src/ai/aiTypes'
import {
  MAX_HISTORY_TURNS,
  SecurityAiController,
  chatHistory,
  failureState,
  initialModel,
  isAnalysis,
  parsePanelMessage,
  prepareQuestion,
  type AiPanelModel,
  type ChatEntry,
  type SecurityAiBackend,
} from '../src/ai/securityAiController'
import { MASK } from '../src/security/redaction'
import { FindingsStore } from '../src/state/findingsStore'
import { buildAiPanelHtml } from '../src/ui/aiHtml'
import { buildDetailHtml } from '../src/ui/detailHtml'

// --------------------------------------------------------------------------
// Fabriques
// --------------------------------------------------------------------------

const DISCLAIMER =
  'Explication générée par une IA à partir du signalement produit par les ' +
  'moteurs de détection. La gravité affichée reste celle du moteur déterministe.'

function health(overrides: Partial<SecurityAiHealth> = {}): SecurityAiHealth {
  return {
    status: 'ok',
    available: true,
    chat_available: true,
    provider_configured: true,
    assistant_enabled: true,
    chat_enabled: true,
    model: 'gpt-4o-mini',
    reason: '',
    disclaimer: DISCLAIMER,
    max_context_findings: 25,
    modifies_findings: false,
    modifies_severity: false,
    requires_wazuh: false,
    ...overrides,
  }
}

function analysis(overrides: Partial<SecurityFindingAiAnalysis> = {}): SecurityFindingAiAnalysis {
  return {
    finding_id: 'finding-1',
    project_uid: 'projet-a',
    ai_generated: true,
    disclaimer: DISCLAIMER,
    model: 'gpt-4o-mini',
    analyzed_at: '2026-09-28T10:00:00Z',
    cached: false,
    category: 'SECRET',
    deterministic_severity: 'CRITICAL',
    deterministic_confidence: 'HIGH',
    deterministic_title: "Clé d'API OpenAI écrite en dur",
    deterministic_remediation: 'Déplacez la clé hors du dépôt.',
    detection_engine: 'secret-scanner',
    file: 'backend/config.py',
    line: 24,
    explanation: 'Une clé écrite en dur est lisible par quiconque accède au dépôt.',
    why_it_matters: 'Elle permet de consommer le service au nom du projet.',
    project_impact: 'Projet Python exposant une API.',
    evidence_interpretation: 'La preuve montre un préfixe masqué.',
    recommendation: 'Révoquez la clé et lisez-la depuis l’environnement.',
    remediation_steps: ['Révoquer la clé', 'La lire depuis l’environnement'],
    secure_example: 'import os\nkey = os.environ["OPENAI_API_KEY"]',
    secure_example_language: 'python',
    related_concepts: ['Gestion des secrets'],
    developer_summary: 'Clé en dur : à révoquer.',
    insufficient_context: false,
    missing_information: [],
    confidence: 0.82,
    project_context_available: true,
    related_findings_considered: 1,
    ...overrides,
  }
}

function summary(overrides: Partial<SecurityFindingsAiSummary> = {}): SecurityFindingsAiSummary {
  return {
    project_uid: 'projet-a',
    ai_generated: true,
    disclaimer: DISCLAIMER,
    model: 'gpt-4o-mini',
    analyzed_at: '2026-09-28T10:00:00Z',
    summary: 'Les signalements relèvent surtout de secrets en dur.',
    themes: ['Secrets dans la configuration'],
    relationships: ['Deux signalements dans le même fichier'],
    priority_order: ["Clé d'API OpenAI écrite en dur"],
    insufficient_context: false,
    missing_information: [],
    findings_considered: 2,
    findings_available: 2,
    truncated: false,
    severity_counts: { total: 2, critical: 1, high: 1, medium: 0, low: 0, by_category: {} },
    project_context_available: true,
    ...overrides,
  }
}

function chatResponse(overrides: Partial<SecurityChatResponse> = {}): SecurityChatResponse {
  return {
    project_uid: 'projet-a',
    ai_generated: true,
    disclaimer: DISCLAIMER,
    model: 'gpt-4o-mini',
    answered_at: '2026-09-28T10:00:00Z',
    question: 'Quels secrets ?',
    answer: 'Deux secrets ont été relevés.',
    insufficient_context: false,
    missing_information: [],
    related_concepts: [],
    findings_considered: 2,
    findings_available: 2,
    truncated: false,
    project_context_available: true,
    history_turns_used: 0,
    ...overrides,
  }
}

/** Faux backend : enregistre les appels, répond ce qu'on lui dit. */
class FakeBackend implements SecurityAiBackend {
  calls: { method: string; projectUid?: string; args: unknown[] }[] = []
  healthResult: SecurityAiHealth | Error = health()
  analysisResult: unknown = analysis()
  summaryResult: unknown = summary()
  chatResult: unknown | ((request: SecurityChatRequest) => unknown) = chatResponse()

  async securityAiHealth(): Promise<SecurityAiHealth> {
    this.calls.push({ method: 'health', args: [] })
    if (this.healthResult instanceof Error) {
      throw this.healthResult
    }
    return this.healthResult
  }

  async analyzeFindingWithAi(
    projectUid: string,
    findingId: string,
    options?: { force?: boolean }
  ): Promise<SecurityFindingAiAnalysis> {
    this.calls.push({ method: 'analyze', projectUid, args: [findingId, options] })
    if (this.analysisResult instanceof Error) {
      throw this.analysisResult
    }
    return this.analysisResult as SecurityFindingAiAnalysis
  }

  async summarizeFindingsWithAi(
    projectUid: string,
    request: { finding_ids: string[] }
  ): Promise<SecurityFindingsAiSummary> {
    this.calls.push({ method: 'summary', projectUid, args: [request] })
    if (this.summaryResult instanceof Error) {
      throw this.summaryResult
    }
    return this.summaryResult as SecurityFindingsAiSummary
  }

  async askSecurityChat(
    projectUid: string,
    request: SecurityChatRequest
  ): Promise<SecurityChatResponse> {
    this.calls.push({ method: 'chat', projectUid, args: [request] })
    const result =
      typeof this.chatResult === 'function' ? this.chatResult(request) : this.chatResult
    if (result instanceof Error) {
      throw result
    }
    return result as SecurityChatResponse
  }
}

function controller(backend: FakeBackend, projectUid: () => string | undefined = () => 'projet-a') {
  const models: AiPanelModel[] = []
  const instance = new SecurityAiController({
    backend,
    projectUid,
    onChange: (model) => models.push(model),
  })
  return { instance, models }
}

// --------------------------------------------------------------------------
// Client HTTP
// --------------------------------------------------------------------------

const realFetch = globalThis.fetch

afterEach(() => {
  ;(globalThis as { fetch: unknown }).fetch = realFetch
})

function stubFetch(
  handler: (url: string, init?: RequestInit) => { status?: number; body: unknown }
): { url: string; init?: RequestInit }[] {
  const seen: { url: string; init?: RequestInit }[] = []
  ;(globalThis as { fetch: unknown }).fetch = async (input: unknown, init?: RequestInit) => {
    const url = String(input)
    seen.push({ url, init })
    const { status = 200, body } = handler(url, init)
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })
  }
  return seen
}

describe('BackendClient — assistant IA de sécurité', () => {
  const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })

  it('lit l’état de l’assistant sur sa route dédiée', async () => {
    const seen = stubFetch(() => ({ body: health() }))
    const result = await client.securityAiHealth()

    assert.equal(seen[0]?.url, 'http://127.0.0.1:8000/api/security/ai/health')
    assert.equal(seen[0]?.init?.method, 'GET')
    assert.equal(result.available, true)
  })

  it('demande l’explication d’un finding existant sans envoyer de corps', async () => {
    const seen = stubFetch(() => ({ body: analysis() }))
    await client.analyzeFindingWithAi('projet a/b', 'finding#1')

    assert.equal(
      seen[0]?.url,
      'http://127.0.0.1:8000/api/project/projet%20a%2Fb/findings/finding%231/ai-analysis'
    )
    assert.equal(seen[0]?.init?.method, 'POST')
    // Aucun contenu ne part : le backend relit le finding depuis sa base.
    assert.equal(seen[0]?.init?.body, undefined)
  })

  it('transmet `force` seulement quand il est demandé', async () => {
    const seen = stubFetch(() => ({ body: analysis() }))
    await client.analyzeFindingWithAi('p', 'f', { force: true })

    assert.match(seen[0]?.url ?? '', /\/ai-analysis\?force=true$/)
  })

  it('envoie la question et l’historique tels quels au chat', async () => {
    const seen = stubFetch(() => ({ body: chatResponse() }))
    const request: SecurityChatRequest = {
      question: 'Quels secrets ?',
      history: [{ role: 'user', message: 'bonjour' }],
      finding_id: null,
    }
    await client.askSecurityChat('projet-a', request)

    assert.equal(seen[0]?.url, 'http://127.0.0.1:8000/api/project/projet-a/ai/chat')
    assert.deepEqual(JSON.parse(String(seen[0]?.init?.body)), request)
  })

  it('envoie la sélection au résumé', async () => {
    const seen = stubFetch(() => ({ body: summary() }))
    await client.summarizeFindingsWithAi('projet-a', { finding_ids: ['x'] })

    assert.equal(seen[0]?.url, 'http://127.0.0.1:8000/api/project/projet-a/ai/summary')
    assert.deepEqual(JSON.parse(String(seen[0]?.init?.body)), { finding_ids: ['x'] })
  })

  it('traduit un 503 en BackendError portant la raison du backend', async () => {
    stubFetch(() => ({
      status: 503,
      body: { detail: { error: 'Assistant IA indisponible : aucune clé API' } },
    }))

    await assert.rejects(
      () => client.analyzeFindingWithAi('p', 'f'),
      (error: unknown) =>
        error instanceof BackendError &&
        error.status === 503 &&
        (error.detail ?? '').includes('aucune clé API')
    )
  })
})

// --------------------------------------------------------------------------
// Expurgation côté extension
// --------------------------------------------------------------------------

describe('redactFreeText — ce qui sort de l’éditeur', () => {
  it('masque les clés reconnues par le moteur de secrets', () => {
    const cases = [
      'sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD',
      'AKIAIOSFODNN7EXAMPLE',
      'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
    ]
    for (const secret of cases) {
      const redacted = redactFreeText(`Pourquoi ${secret} est-il signalé ?`)
      assert.ok(!redacted.includes(secret), `${secret} est sorti en clair`)
      assert.ok(redacted.includes(MASK))
    }
  })

  it('masque la valeur d’une affectation de mot de passe', () => {
    const redacted = redactFreeText('DB_PASSWORD="Sup3rS3cretValue!" dans config.py')
    assert.ok(!redacted.includes('Sup3rS3cretValue'))
    assert.ok(redacted.includes('config.py'))
  })

  it('masque un jeton long d’un fournisseur inconnu du catalogue', () => {
    const token = 'zz9Qx81mNpL0vR4tY7wK2sD5fG3hJ6'
    assert.ok(!redactFreeText(`le jeton ${token} fuit`).includes(token))
  })

  it('laisse une question ordinaire intacte', () => {
    const question = 'Comment corriger unauthenticated_endpoint sur /admin/users ?'
    assert.equal(redactFreeText(question), question)
  })

  it('borne la longueur de la question', () => {
    assert.equal(redactFreeText('a '.repeat(2000)).length, MAX_QUESTION_LENGTH)
  })

  it('signale qu’une question a été modifiée avant l’envoi', () => {
    assert.deepEqual(prepareQuestion('Bonjour'), { question: 'Bonjour', redacted: false })
    assert.equal(prepareQuestion('clé AKIAIOSFODNN7EXAMPLE').redacted, true)
  })
})

// --------------------------------------------------------------------------
// Contrôleur : explication d'un finding
// --------------------------------------------------------------------------

describe('SecurityAiController — explication d’un finding', () => {
  it('n’envoie que le projet et l’identifiant du finding', async () => {
    const backend = new FakeBackend()
    const { instance } = controller(backend)

    await instance.analyze('finding-1', 'Titre')

    assert.equal(backend.calls.length, 1)
    assert.deepEqual(backend.calls[0], {
      method: 'analyze',
      projectUid: 'projet-a',
      args: ['finding-1', { force: false }],
    })
    assert.equal(instance.model.status, 'ready')
    assert.equal(instance.model.analysis?.explanation.startsWith('Une clé'), true)
  })

  it('passe par l’état « en cours » avant la réponse', async () => {
    const backend = new FakeBackend()
    const { instance, models } = controller(backend)

    await instance.analyze('finding-1', 'Titre')

    assert.equal(models[0]?.status, 'loading')
    assert.equal(models.at(-1)?.status, 'ready')
  })

  it('vise le projet ouvert au moment de l’appel', async () => {
    const backend = new FakeBackend()
    let current = 'projet-a'
    const { instance } = controller(backend, () => current)

    await instance.analyze('f', 't')
    current = 'projet-b'
    await instance.analyze('f', 't')

    assert.deepEqual(
      backend.calls.map((call) => call.projectUid),
      ['projet-a', 'projet-b']
    )
  })

  it('n’appelle rien sans projet établi', async () => {
    const backend = new FakeBackend()
    const { instance } = controller(backend, () => undefined)

    await instance.analyze('f', 't')
    await instance.ask('Une question')
    await instance.summarize()

    assert.equal(backend.calls.length, 0)
    assert.equal(instance.model.status, 'error')
  })

  it('un 503 se lit « indisponible », avec la raison du backend', async () => {
    const backend = new FakeBackend()
    backend.analysisResult = new BackendError(
      'Service indisponible',
      503,
      'Assistant IA indisponible : aucune clé API (OPENAI_API_KEY)'
    )
    const { instance } = controller(backend)

    await instance.analyze('f', 't')

    assert.equal(instance.model.status, 'unavailable')
    assert.match(instance.model.message, /OPENAI_API_KEY/)
    assert.equal(instance.model.analysis, undefined)
  })

  it('une erreur du fournisseur donne un message, jamais une fiche vide', async () => {
    for (const [status, expected] of [
      [429, /Quota/],
      [504, /à temps/],
      [502, /inexploitable/],
      [500, /n’a pas pu répondre/],
    ] as const) {
      const backend = new FakeBackend()
      backend.analysisResult = new BackendError('x', status)
      const { instance } = controller(backend)

      await instance.analyze('f', 't')

      assert.equal(instance.model.status, 'error', `HTTP ${status}`)
      assert.match(instance.model.message, expected)
      assert.equal(instance.model.analysis, undefined)
    }
  })

  it('une réponse malformée est refusée', async () => {
    const malformed: unknown[] = [
      {},
      { ...analysis(), ai_generated: false },
      { ...analysis(), explanation: '   ' },
      { ...analysis(), deterministic_severity: undefined },
      'pas un objet',
      null,
    ]
    for (const body of malformed) {
      const backend = new FakeBackend()
      backend.analysisResult = body
      const { instance } = controller(backend)

      await instance.analyze('f', 't')

      assert.equal(instance.model.status, 'error', JSON.stringify(body))
      assert.equal(instance.model.analysis, undefined)
    }
  })

  it('écarte une réponse arrivée après une demande plus récente', async () => {
    const backend = new FakeBackend()
    let release: (() => void) | undefined
    const slow = new Promise<void>((resolve) => {
      release = resolve
    })
    const original = backend.analyzeFindingWithAi.bind(backend)
    let first = true
    backend.analyzeFindingWithAi = async (projectUid, findingId, options) => {
      if (first) {
        first = false
        await slow
        return analysis({ finding_id: 'ancien', explanation: 'Réponse périmée' })
      }
      return original(projectUid, findingId, options)
    }
    const { instance } = controller(backend)

    const pending = instance.analyze('ancien', 'Ancien')
    await instance.analyze('finding-1', 'Récent')
    release?.()
    await pending

    assert.equal(instance.model.analysis?.finding_id, 'finding-1')
  })

  it('« Refaire l’analyse » force le backend à ignorer son cache', async () => {
    const backend = new FakeBackend()
    const { instance } = controller(backend)

    await instance.analyze('finding-1', 'Titre')
    await instance.reanalyze()

    assert.deepEqual(backend.calls[1]?.args, ['finding-1', { force: true }])
  })

  it('ne touche jamais au registre des findings', async () => {
    const store = new FindingsStore()
    const finding: CodeFinding = {
      finding_uid: 'finding-1',
      scan_uid: 'project:SECRET',
      rule_id: 'secret-scanner',
      category: 'hardcoded_secret',
      category_label: 'Secret exposé',
      cwe: 'CWE-798',
      owasp: null,
      severity: 'CRITICAL',
      severity_label: 'CRITIQUE',
      risk_score: 90,
      risk_band: 'CRITICAL',
      confidence: 0.9,
      source: 'rule',
      source_label: 'secret-scanner',
      title: "Clé d'API OpenAI écrite en dur",
      explanation: '',
      why_dangerous: '',
      potential_impact: [],
      recommendations: [],
      risk_factors: [],
      location: { line_start: 24, line_end: 24, column_start: 0, column_end: 0, snippet: '' },
      file_path: 'backend/config.py',
      fix_available: false,
      fix_summary: '',
      status: 'open',
      status_label: 'Ouvert',
      created_at: '2026-09-28T10:00:00Z',
      detection_engine: 'secret-scanner',
    }
    store.replaceProjectFindings([finding])
    const before = JSON.stringify(store.all())

    // Un backend hostile glisse une gravité et un statut dans sa réponse.
    const backend = new FakeBackend()
    backend.analysisResult = { ...analysis(), severity: 'LOW', status: 'dismissed' }
    const { instance } = controller(backend)
    await instance.analyze('finding-1', 'Titre')

    assert.equal(JSON.stringify(store.all()), before)
    assert.equal(store.get('finding-1')?.severity, 'CRITICAL')
  })
})

// --------------------------------------------------------------------------
// Contrôleur : résumé et chat
// --------------------------------------------------------------------------

describe('SecurityAiController — résumé et chat', () => {
  it('le résumé porte sa couverture jusqu’à l’écran', async () => {
    const backend = new FakeBackend()
    backend.summaryResult = summary({ findings_considered: 25, findings_available: 300, truncated: true })
    const { instance } = controller(backend)

    await instance.summarize()

    assert.equal(instance.model.status, 'ready')
    const html = buildAiPanelHtml(instance.model, 'n')
    assert.match(html, /25 signalement\(s\) lu\(s\) sur 300/)
    assert.match(html, /liste tronquée/)
  })

  it('un résumé vide est une erreur', async () => {
    const backend = new FakeBackend()
    backend.summaryResult = { ...summary(), summary: '' }
    const { instance } = controller(backend)

    await instance.summarize()

    assert.equal(instance.model.status, 'error')
  })

  it('la question est expurgée avant de partir', async () => {
    const backend = new FakeBackend()
    const { instance } = controller(backend)

    await instance.ask('Que faire de AKIAIOSFODNN7EXAMPLE dans settings.py ?')

    const request = backend.calls[0]?.args[0] as SecurityChatRequest
    assert.ok(!request.question.includes('AKIAIOSFODNN7EXAMPLE'))
    assert.ok(request.question.includes('settings.py'))
    assert.equal(instance.model.chat[0]?.redacted, true)
  })

  it('affiche la question telle que le backend l’a expurgée', async () => {
    const backend = new FakeBackend()
    backend.chatResult = chatResponse({ question: 'Pourquoi DB_PASSW******** ?' })
    const { instance } = controller(backend)

    await instance.ask('Pourquoi DB_PASSWORD=abc ?')

    assert.equal(instance.model.chat[0]?.question, 'Pourquoi DB_PASSW******** ?')
    assert.equal(instance.model.chat[0]?.redacted, true)
  })

  it('renvoie l’historique des échanges aboutis, borné', async () => {
    const backend = new FakeBackend()
    backend.chatResult = (request: SecurityChatRequest) =>
      chatResponse({ question: request.question, answer: `réponse à ${request.question}` })
    const { instance } = controller(backend)

    for (let index = 0; index < 6; index += 1) {
      await instance.ask(`question ${index}`)
    }

    const last = backend.calls.at(-1)?.args[0] as SecurityChatRequest
    assert.equal(last.history.length, MAX_HISTORY_TURNS)
    assert.equal(last.history.at(-1)?.role, 'assistant')
    assert.equal(last.history.at(-1)?.message, 'réponse à question 4')
    assert.ok(!last.history.some((turn) => turn.message === 'question 0'))
  })

  it('une question posée depuis une explication porte son finding', async () => {
    const backend = new FakeBackend()
    const { instance } = controller(backend)

    await instance.analyze('finding-1', 'Titre')
    await instance.ask('Et en production ?')

    const request = backend.calls.at(-1)?.args[0] as SecurityChatRequest
    assert.equal(request.finding_id, 'finding-1')
  })

  it('une question générale ne porte aucun finding', async () => {
    const backend = new FakeBackend()
    const { instance } = controller(backend)

    instance.showChat()
    await instance.ask('Quel est le risque principal ?')

    const request = backend.calls[0]?.args[0] as SecurityChatRequest
    assert.equal(request.finding_id, null)
  })

  it('un échec de chat reste affiché, et un 503 retire le formulaire', async () => {
    const backend = new FakeBackend()
    const { instance } = controller(backend)
    instance.applyHealth(health())
    backend.chatResult = new BackendError('x', 503, 'Chat de sécurité désactivé')

    await instance.ask('Bonjour ?')

    assert.equal(instance.model.chat[0]?.pending, false)
    assert.match(instance.model.chat[0]?.error ?? '', /désactivé/)
    assert.equal(instance.model.chatAvailable, false)
  })

  it('une réponse de chat malformée est une erreur', async () => {
    const backend = new FakeBackend()
    backend.chatResult = { ai_generated: true, answer: '' }
    const { instance } = controller(backend)

    await instance.ask('Bonjour ?')

    assert.ok(instance.model.chat[0]?.error)
    assert.equal(instance.model.chat[0]?.response, undefined)
  })
})

describe('SecurityAiController — état de l’assistant', () => {
  it('un assistant indisponible est annoncé avec sa raison', async () => {
    const backend = new FakeBackend()
    backend.healthResult = health({
      available: false,
      chat_available: false,
      reason: 'Assistant IA indisponible : aucune clé API',
    })
    const { instance } = controller(backend)

    await instance.refreshHealth()

    assert.equal(instance.model.status, 'unavailable')
    assert.match(instance.model.message, /aucune clé API/)
    assert.equal(instance.model.chatAvailable, false)
  })

  it('un backend sans assistant (404) ne fait rien échouer', async () => {
    const backend = new FakeBackend()
    backend.healthResult = new BackendError('Introuvable', 404)
    const { instance } = controller(backend)

    const result = await instance.refreshHealth()

    assert.equal(result, undefined)
    assert.equal(instance.model.chatAvailable, false)
  })
})

// --------------------------------------------------------------------------
// Fonctions pures
// --------------------------------------------------------------------------

describe('assistant IA — validation et historique', () => {
  it('n’accepte que trois actions de la webview', () => {
    assert.deepEqual(parsePanelMessage({ action: 'ask', question: '  bonjour  ' }), {
      action: 'ask',
      question: 'bonjour',
    })
    assert.deepEqual(parsePanelMessage({ action: 'reanalyze' }), { action: 'reanalyze' })
    assert.deepEqual(parsePanelMessage({ action: 'summarize' }), { action: 'summarize' })

    for (const invalid of [
      undefined,
      null,
      'ask',
      { action: 'ask', question: '' },
      { action: 'ask', question: 42 },
      { action: 'dismiss' },
      { action: 'setSeverity', severity: 'LOW' },
    ]) {
      assert.equal(parsePanelMessage(invalid), undefined, JSON.stringify(invalid))
    }
  })

  it('borne une question trop longue venue de la webview', () => {
    const message = parsePanelMessage({ action: 'ask', question: 'x'.repeat(5000) })
    assert.equal(message?.action === 'ask' && message.question.length, MAX_QUESTION_LENGTH)
  })

  it('l’historique ignore les échanges en cours ou en erreur', () => {
    const entries: ChatEntry[] = [
      { question: 'a', redacted: false, pending: false, response: chatResponse({ answer: 'ra' }) },
      { question: 'b', redacted: false, pending: false, error: 'échec' },
      { question: 'c', redacted: false, pending: true },
    ]
    assert.deepEqual(chatHistory(entries), [
      { role: 'user', message: 'a' },
      { role: 'assistant', message: 'ra' },
    ])
    assert.deepEqual(chatHistory(entries, 0), [])
  })

  it('l’historique repasse par l’expurgation', () => {
    const entries: ChatEntry[] = [
      {
        question: 'ok',
        redacted: false,
        pending: false,
        response: chatResponse({ answer: 'la clé AKIAIOSFODNN7EXAMPLE est exposée' }),
      },
    ]
    assert.ok(!JSON.stringify(chatHistory(entries)).includes('AKIAIOSFODNN7EXAMPLE'))
  })

  it('une erreur inconnue donne un message générique, pas une trace', () => {
    const state = failureState(new TypeError('x is undefined'))
    assert.equal(state.status, 'error')
    assert.ok(!state.message.includes('undefined'))
  })

  it('reconnaît une explication valide', () => {
    assert.equal(isAnalysis(analysis()), true)
  })
})

// --------------------------------------------------------------------------
// Rendu
// --------------------------------------------------------------------------

function ready(overrides: Partial<SecurityFindingAiAnalysis> = {}): AiPanelModel {
  return {
    ...initialModel({ kind: 'analysis', findingId: 'finding-1', findingTitle: 'Titre' }),
    status: 'ready',
    analysis: analysis(overrides),
    chatAvailable: true,
    disclaimer: DISCLAIMER,
  }
}

describe('fenêtre de l’assistant — rendu', () => {
  it('marque toute explication comme générée par IA, avec la mise en garde', () => {
    const html = buildAiPanelHtml(ready(), 'n0nce')
    assert.match(html, /Généré par IA/)
    assert.ok(html.includes('La gravité affichée reste celle du moteur déterministe'))
  })

  it('affiche la gravité du moteur, et elle seule', () => {
    // Un champ `severity` glissé dans la réponse n'alimente rien.
    const model = ready({ deterministic_severity: 'CRITICAL' })
    ;(model.analysis as unknown as Record<string, unknown>).severity = 'LOW'
    const html = buildAiPanelHtml(model, 'n')

    assert.match(html, /<span class="badge critical">CRITICAL<\/span>/)
    assert.ok(!html.includes('>LOW<'))
    assert.match(html, /L’IA ne les modifie pas/)
  })

  it('présente les rubriques de l’explication', () => {
    const html = buildAiPanelHtml(ready(), 'n')
    for (const expected of [
      'Explication',
      'Pourquoi c’est important',
      'Impact pour ce projet',
      'Lecture de la preuve',
      'Recommandation',
      'Exemple sécurisé',
      'Concepts liés',
      'Remédiation proposée par le moteur',
    ]) {
      assert.ok(html.includes(expected), expected)
    }
  })

  it('échappe le texte de l’IA, y compris l’exemple de code', () => {
    const html = buildAiPanelHtml(
      ready({
        explanation: '<script>alert(1)</script>',
        secure_example: '<img src=x onerror=alert(1)>',
        deterministic_title: '"><svg onload=alert(1)>',
      }),
      'n'
    )
    assert.ok(!html.includes('<script>alert(1)</script>'))
    assert.ok(!html.includes('<img src=x'))
    assert.ok(!html.includes('<svg onload'))
    assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'))
  })

  it('annonce un contexte insuffisant plutôt que de le masquer', () => {
    const html = buildAiPanelHtml(
      ready({ insufficient_context: true, missing_information: ['Fichier non analysé'] }),
      'n'
    )
    assert.match(html, /Contexte insuffisant/)
    assert.match(html, /Fichier non analysé/)
  })

  it('dit quand l’explication a été produite sans contexte de projet', () => {
    const html = buildAiPanelHtml(ready({ project_context_available: false }), 'n')
    assert.match(html, /Aucun contexte de projet/)
  })

  it('affiche l’état « en cours »', () => {
    const html = buildAiPanelHtml(
      { ...initialModel({ kind: 'analysis', findingId: 'f', findingTitle: 'T' }), status: 'loading' },
      'n'
    )
    assert.match(html, /Analyse IA en cours/)
    assert.ok(!html.includes('Généré par IA'))
  })

  it('l’état indisponible rappelle que la détection continue', () => {
    const html = buildAiPanelHtml(
      { ...initialModel(), status: 'unavailable', message: 'aucune clé API' },
      'n'
    )
    assert.match(html, /Assistant IA indisponible/)
    assert.match(html, /aucune clé API/)
    assert.match(html, /ne dépendent pas de l’assistant/)
    // Pas de formulaire de chat vers un assistant absent.
    assert.ok(!html.includes('id="chat"'))
  })

  it('l’état d’erreur n’affiche aucune explication', () => {
    const html = buildAiPanelHtml(
      { ...ready(), status: 'error', message: 'réponse inexploitable' },
      'n'
    )
    assert.match(html, /L’analyse IA a échoué/)
    assert.ok(!html.includes('Généré par IA'))
  })

  it('le chat marque les réponses et signale une question masquée', () => {
    const model: AiPanelModel = {
      ...initialModel(),
      status: 'ready',
      chatAvailable: true,
      chat: [
        {
          question: 'clé AKIA********',
          redacted: true,
          pending: false,
          response: chatResponse({ answer: '<b>réponse</b>' }),
        },
      ],
    }
    const html = buildAiPanelHtml(model, 'n')
    assert.match(html, /Assistant \(IA\)/)
    assert.match(html, /Généré par IA/)
    assert.match(html, /masquées avant l’envoi/)
    assert.ok(html.includes('&lt;b&gt;réponse&lt;/b&gt;'))
  })

  it('bloque l’envoi pendant qu’une réponse est attendue', () => {
    const model: AiPanelModel = {
      ...initialModel(),
      chatAvailable: true,
      chat: [{ question: 'q', redacted: false, pending: true }],
    }
    const html = buildAiPanelHtml(model, 'n')
    assert.match(html, /rédige sa réponse/)
    assert.match(html, /id="send" disabled/)
  })

  it('la page n’autorise que ses propres style et script', () => {
    const html = buildAiPanelHtml(ready(), 'abc123')
    assert.match(html, /default-src 'none'/)
    assert.match(html, /connect-src 'none'/)
    assert.match(html, /script-src 'nonce-abc123'/)
    assert.ok(!html.includes('unsafe-inline'))
    assert.ok(!/https?:\/\//.test(html.replace(/http-equiv/g, '')))
  })
})

describe('assistant IA — aucun champ de contenu ni de décision', () => {
  // Vérification mot à mot : le balayage par sous-chaîne du test de
  // contrat confondrait `insufficient_context` avec un champ de texte.
  const FILE_CONTENT = new Set([
    'content',
    'file_content',
    'source',
    'source_code',
    'snippet',
    'excerpt',
    'raw',
    'body',
    'code',
  ])
  const DECISION = new Set(['severity', 'risk_score', 'status', 'score'])

  const request: SecurityChatRequest = { question: 'q', history: [], finding_id: null }
  const samples: Record<string, object> = {
    SecurityAiHealth: health(),
    SecurityFindingAiAnalysis: analysis(),
    SecurityFindingsAiSummary: summary(),
    SecurityChatResponse: chatResponse(),
    SecurityChatRequest: request,
    SecurityChatTurn: { role: 'user', message: 'm' },
  }

  for (const [name, sample] of Object.entries(samples)) {
    it(`${name} ne porte aucun champ de contenu de fichier`, () => {
      for (const field of Object.keys(sample)) {
        assert.ok(!FILE_CONTENT.has(field), `${name}.${field}`)
      }
    })

  }

  // Les sorties d'IA seulement : `SecurityAiHealth.status` est l'état du
  // service (« ok »), pas celui d'un finding.
  for (const name of [
    'SecurityFindingAiAnalysis',
    'SecurityFindingsAiSummary',
    'SecurityChatResponse',
  ]) {
    it(`${name} ne porte aucune gravité ni aucun statut produit par l’IA`, () => {
      for (const field of Object.keys(samples[name] ?? {})) {
        assert.ok(!DECISION.has(field), `${name}.${field}`)
      }
    })
  }
})

describe('fiche de détail — bouton IA', () => {
  const finding = {
    finding_uid: 'f',
    severity: 'HIGH',
    title: 'Titre',
    category: 'hardcoded_secret',
    category_label: 'Secret',
    rule_id: 'secret-scanner',
    location: { line_start: 1, line_end: 1, column_start: 0, column_end: 0, snippet: '' },
    risk_factors: [],
  } as unknown as CodeFinding

  it('n’apparaît pas par défaut', () => {
    assert.ok(!buildDetailHtml(finding, 'n').includes('id="ai"'))
  })

  it('apparaît quand une action IA est annoncée', () => {
    const html = buildDetailHtml(finding, 'n', { aiAvailable: true })
    assert.match(html, /<button id="ai"/)
    assert.match(html, /'fix', 'dismiss', 'ai'/)
  })
})
