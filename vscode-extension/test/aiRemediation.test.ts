/**
 * Tests de la remédiation assistée côté extension (phase 7).
 *
 * Le cœur (`remediation/aiFix.ts`) est éprouvé en Node pur : le document
 * est un double qui compte ses écritures, ce qui permet de prouver qu'il
 * n'est touché ni avant la confirmation, ni après un refus — et qu'un
 * échec en cours d'application ramène le fichier à l'original.
 *
 *     AVANT CONFIRMATION  aucune écriture, quelle que soit la réponse.
 *     ÉLIGIBILITÉ         `.env`, clés, certificats, identifiants, verrous :
 *                         jamais lus pour un correctif, jamais modifiés.
 *     CE QUI PART         un extrait borné et expurgé, jamais le fichier.
 *     VALIDATION          proposition hors du finding, secret écrit, valeur
 *                         masquée recopiée, champ interdit : rejet en bloc.
 *     FICHIER MODIFIÉ     la proposition est périmée : rien n'est appliqué.
 *     ÉCHEC               le fichier revient à l'original.
 *     VÉRIFICATION        c'est la nouvelle analyse qui dit « corrigé » —
 *                         l'application seule ne change pas le registre.
 */

import assert from 'node:assert/strict'
import { afterEach, describe, it } from 'node:test'
import Module from 'node:module'

import { BackendClient, type CodeFinding } from '../src/api/backendClient'
import { contentHash } from '../src/analysis/contentHash'
import type { SecurityFixProposal, SecurityFixRequest } from '../src/ai/aiTypes'
import {
  SecurityAiController,
  initialModel,
  parsePanelMessage,
  type AiPanelModel,
  type FixPanelState,
  type SecurityAiBackend,
} from '../src/ai/securityAiController'
import {
  FIX_CONTEXT_LINES,
  applyBoundedFix,
  confirmAndApply,
  buildFixRequest,
  fixEligibility,
  isLockfile,
  isProtectedPath,
  locateTargetLine,
  proposedText,
  splitLines,
  stillDetected,
  validateProposal,
  type EditableDocument,
  type ProposalContext,
} from '../src/remediation/aiFix'
import { FindingsStore } from '../src/state/findingsStore'
import { buildAiPanelHtml } from '../src/ui/aiHtml'
import { buildDetailHtml } from '../src/ui/detailHtml'

// --------------------------------------------------------------------------
// Fabriques
// --------------------------------------------------------------------------

const SECRET_VALUE = 'sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD'

const FILE = [
  'import os',
  '',
  '',
  'class Settings:',
  '    """Configuration."""',
  '',
  `    OPENAI_KEY = "${SECRET_VALUE}"`,
  '    MODEL = "gpt-4o-mini"',
  '',
].join('\n')

function finding(overrides: Partial<CodeFinding> = {}): CodeFinding {
  return {
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
    location: { line_start: 7, line_end: 7, column_start: 0, column_end: 0, snippet: '' },
    file_path: 'backend/config.py',
    fix_available: false,
    fix_summary: '',
    status: 'open',
    status_label: 'Ouvert',
    created_at: '2026-09-28T10:00:00Z',
    detection_engine: 'secret-scanner',
    ...overrides,
  }
}

function proposal(overrides: Partial<SecurityFixProposal> = {}): SecurityFixProposal {
  return {
    finding_id: 'finding-1',
    project_uid: 'projet-a',
    kind: 'security',
    ai_generated: true,
    disclaimer: 'Modification proposée par une IA. Rien n’est appliqué sans votre confirmation.',
    model: 'gpt-4o-mini',
    generated_at: '2026-09-28T10:00:00Z',
    category: 'SECRET',
    deterministic_severity: 'CRITICAL',
    deterministic_title: "Clé d'API OpenAI écrite en dur",
    available: true,
    refusal: '',
    file: 'backend/config.py',
    base_content_hash: contentHash(FILE),
    start_line: 7,
    end_line: 7,
    replacement_lines: ['    OPENAI_KEY = os.environ["OPENAI_API_KEY"]'],
    explanation: 'La clé est lue depuis l’environnement.',
    reason: 'Aucune valeur ne reste dans le code.',
    warnings: ['Définissez OPENAI_API_KEY.'],
    manual_steps: ['Révoquez la clé exposée.'],
    ...overrides,
  }
}

function context(overrides: Partial<ProposalContext> = {}): ProposalContext {
  return {
    findingId: 'finding-1',
    relativePath: 'backend/config.py',
    baseHash: contentHash(FILE),
    targetLine: 7,
    lines: splitLines(FILE).lines,
    ...overrides,
  }
}

/**
 * Document de test : compte ses écritures et peut échouer sur commande.
 *
 * `corrupt` simule un éditeur qui applique autre chose que demandé ;
 * `failSave` un enregistrement refusé ; `failRestore` un retour arrière
 * impossible.
 */
class FakeDocument implements EditableDocument {
  text: string
  dirty = false
  writes = 0
  saves = 0
  failReplace: 'false' | 'throw' | undefined
  corrupt = false
  failSave = false
  failRestore = false

  constructor(text: string) {
    this.text = text
  }

  getText(): string {
    return this.text
  }

  isDirty(): boolean {
    return this.dirty
  }

  async replaceLines(start: number, end: number, lines: readonly string[]): Promise<boolean> {
    if (this.failReplace === 'throw') {
      throw new Error('éditeur fermé')
    }
    if (this.failReplace === 'false') {
      return false
    }
    this.writes += 1
    const { lines: current, eol } = splitLines(this.text)
    const next = [...current.slice(0, start - 1), ...lines, ...current.slice(end)]
    this.text = next.join(eol) + (this.corrupt ? '\n# inattendu' : '')
    this.dirty = true
    return true
  }

  async replaceAll(text: string): Promise<boolean> {
    if (this.failRestore) {
      return false
    }
    this.writes += 1
    this.text = text
    return true
  }

  async save(): Promise<boolean> {
    this.saves += 1
    if (this.failSave) {
      return false
    }
    this.dirty = false
    return true
  }
}

// --------------------------------------------------------------------------
// Éligibilité
// --------------------------------------------------------------------------

describe('remédiation assistée — éligibilité', () => {
  it('un secret dans un fichier source est éligible', () => {
    assert.deepEqual(fixEligibility(finding()), { ok: true })
  })

  it('un fichier protégé n’est jamais proposé à la modification', () => {
    for (const file of [
      '.env',
      '.env.production',
      'config/id_rsa',
      'certs/server.pem',
      'tls/server.key',
      'certs/site.crt',
      'certs/ca.cer',
      'keys/store.p12',
      'credentials.json',
      '.npmrc',
    ]) {
      const verdict = fixEligibility(finding({ file_path: file }))
      assert.equal(verdict.ok, false, file)
      assert.match(verdict.ok ? '' : verdict.reason, /manuelle|protégé/, file)
      assert.equal(isProtectedPath(file), true, file)
    }
  })

  it('un modèle d’environnement reste éligible', () => {
    assert.equal(isProtectedPath('.env.example'), false)
    assert.equal(isProtectedPath('src/settings.py'), false)
  })

  it('une dépendance d’un fichier de verrouillage renvoie au manifeste', () => {
    const dependency = finding({
      scan_uid: 'project:DEPENDENCY',
      category: 'vulnerable_dependency',
      title: 'express 4.17.1 — GHSA-29mw-wpgm-hmr9',
      file_path: 'package-lock.json',
    })
    const verdict = fixEligibility(dependency)
    assert.equal(verdict.ok, false)
    assert.match(verdict.ok ? '' : verdict.reason, /verrouillage/)
    assert.equal(isLockfile('frontend/yarn.lock'), true)
    assert.deepEqual(fixEligibility({ ...dependency, file_path: 'package.json' }), { ok: true })
  })

  it('un finding refermé, sans fichier ou d’historique Git est refusé', () => {
    assert.equal(fixEligibility(finding({ status: 'dismissed' })).ok, false)
    assert.equal(fixEligibility(finding({ file_path: '' })).ok, false)
    assert.equal(fixEligibility(finding({ scan_uid: 'project:GIT' })).ok, false)
  })
})

// --------------------------------------------------------------------------
// Ce qui part vers le backend
// --------------------------------------------------------------------------

describe('remédiation assistée — requête', () => {
  it('envoie un extrait borné, jamais le fichier entier', () => {
    const long = Array.from({ length: 100 }, (_, index) => `ligne_${index + 1} = ${index}`)
    long[49] = `    KEY = "${SECRET_VALUE}"`
    const text = long.join('\n')

    const built = buildFixRequest(finding({ location: { line_start: 50, line_end: 50, column_start: 0, column_end: 0, snippet: '' } }), text, 'backend/config.py', 'python')

    assert.equal(built.ok, true)
    if (!built.ok) return
    assert.equal(built.request.excerpt_start_line, 50 - FIX_CONTEXT_LINES)
    assert.equal(built.request.excerpt_lines.length, 2 * FIX_CONTEXT_LINES + 1)
    assert.equal(built.request.target_line, 50)
    // L'empreinte porte sur le fichier réel : c'est elle qui sera comparée
    // avant d'écrire.
    assert.equal(built.request.content_hash, contentHash(text))
  })

  it('expurge la ligne du secret et conserve l’indentation', () => {
    const built = buildFixRequest(finding(), FILE, 'backend/config.py', 'python')
    assert.equal(built.ok, true)
    if (!built.ok) return

    const payload = JSON.stringify(built.request)
    assert.ok(!payload.includes(SECRET_VALUE), 'le secret est parti en clair')
    assert.ok(built.request.excerpt_lines[6]?.startsWith('    OPENAI_KEY = "sk-proj'))
    assert.equal(built.request.excerpt_lines[3], 'class Settings:')
    assert.equal(built.request.excerpt_lines[7], '    MODEL = "gpt-4o-mini"')
  })

  it('ne porte aucun champ de contenu de fichier', () => {
    const built = buildFixRequest(finding(), FILE, 'backend/config.py', 'python')
    assert.equal(built.ok, true)
    if (!built.ok) return
    const request: SecurityFixRequest = built.request
    for (const field of ['content', 'file_content', 'text', 'workspace']) {
      assert.ok(!(field in request), field)
    }
  })

  it('trouve la ligne de déclaration d’une dépendance par son nom exact', () => {
    const dependency = finding({
      scan_uid: 'project:DEPENDENCY',
      category: 'vulnerable_dependency',
      title: 'express 4.17.1 — GHSA-29mw-wpgm-hmr9',
      file_path: 'package.json',
    })
    const manifest = ['{', '  "dependencies": {', '    "express-session": "1.0.0",', '    "express": "4.17.1"', '  }', '}']

    assert.equal(locateTargetLine(dependency, manifest), 4)
    assert.equal(locateTargetLine(dependency, ['{}']), undefined)
  })

  it('refuse une ligne de finding qui n’existe plus', () => {
    const built = buildFixRequest(
      finding({ location: { line_start: 400, line_end: 400, column_start: 0, column_end: 0, snippet: '' } }),
      FILE,
      'backend/config.py',
      'python'
    )
    assert.equal(built.ok, false)
  })
})

describe('BackendClient — correctif assisté', () => {
  const realFetch = globalThis.fetch
  afterEach(() => {
    ;(globalThis as { fetch: unknown }).fetch = realFetch
  })

  it('demande une proposition sur la route du finding, avec l’extrait', async () => {
    const seen: { url: string; body: unknown }[] = []
    ;(globalThis as { fetch: unknown }).fetch = async (input: unknown, init?: RequestInit) => {
      seen.push({ url: String(input), body: JSON.parse(String(init?.body)) })
      return new Response(JSON.stringify(proposal()), { status: 200 })
    }
    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    const built = buildFixRequest(finding(), FILE, 'backend/config.py', 'python')
    assert.equal(built.ok, true)
    if (!built.ok) return

    await client.proposeFixWithAi('projet-a', 'finding-1', built.request)

    assert.equal(
      seen[0]?.url,
      'http://127.0.0.1:8000/api/project/projet-a/findings/finding-1/ai-fix'
    )
    assert.deepEqual(seen[0]?.body, built.request)
  })
})

// --------------------------------------------------------------------------
// Validation de la proposition
// --------------------------------------------------------------------------

describe('remédiation assistée — validation', () => {
  it('accepte une proposition bornée qui retire le secret', () => {
    assert.equal(validateProposal(proposal(), context()).ok, true)
  })

  const rejected: [string, unknown, RegExp][] = [
    ['réponse non marquée IA', { ...proposal(), ai_generated: false }, /inexploitable/],
    ['réponse illisible', 'pas un objet', /inexploitable/],
    ['champ severity', { ...proposal(), severity: 'LOW' }, /interdit/],
    ['champ status', { ...proposal(), status: 'fixed' }, /interdit/],
    ['autre finding', proposal({ finding_id: 'autre' }), /ce signalement/],
    ['autre fichier', proposal({ file: 'backend/other.py' }), /autre fichier/],
    ['fichier modifié depuis', proposal({ base_content_hash: 'b'.repeat(64) }), /a changé/],
    ['plage hors fichier', proposal({ start_line: 7, end_line: 40 }), /sort du fichier/],
    ['plage inversée', proposal({ start_line: 8, end_line: 7 }), /sort du fichier/],
    ['hors ligne du finding', proposal({ start_line: 8, end_line: 8 }), /ligne du signalement/],
    ['valeur masquée recopiée', proposal({ replacement_lines: ['    OPENAI_KEY = "sk-proj-********"'] }), /masquée/],
    ['[REDACTED] recopié', proposal({ replacement_lines: ['    OPENAI_KEY = "[REDACTED]"'] }), /masquée/],
    ['nouveau secret écrit', proposal({ replacement_lines: [`    OPENAI_KEY = "${SECRET_VALUE.replace('abc', 'xyz')}"`] }), /secret/],
    ['clé AWS écrite', proposal({ replacement_lines: ["    AWS = 'AKIAIOSFODNN7EXAMPLE'"] }), /secret/],
    ['saut de ligne', proposal({ replacement_lines: ['a\nb'] }), /inexploitable/],
    ['suppression déguisée', proposal({ replacement_lines: ['   '] }), /supprimait/],
    ['lignes non textuelles', { ...proposal(), replacement_lines: [42] }, /inexploitable/],
    ['plage non entière', { ...proposal(), start_line: '7' }, /inexploitable/],
  ]

  for (const [label, raw, expected] of rejected) {
    it(`rejette : ${label}`, () => {
      const verdict = validateProposal(raw, context())
      assert.equal(verdict.ok, false)
      assert.match(verdict.ok ? '' : verdict.reason, expected)
    })
  }

  it('rejette : plage trop grande', () => {
    const lines = Array.from({ length: 30 }, (_, index) => `x${index} = ${index}`)
    const verdict = validateProposal(
      proposal({ start_line: 1, end_line: 11, replacement_lines: Array(11).fill('y = 0') }),
      context({ lines })
    )
    assert.equal(verdict.ok, false)
    assert.match(verdict.ok ? '' : verdict.reason, /trop de lignes/)
  })

  it('rejette : aucun changement', () => {
    const verdict = validateProposal(
      proposal({ start_line: 1, end_line: 1, replacement_lines: ['a = 1'] }),
      context({ lines: ['a = 1', 'b = 2'], targetLine: 1 })
    )
    assert.equal(verdict.ok, false)
    assert.match(verdict.ok ? '' : verdict.reason, /ne modifie rien/)
  })

  it('une proposition indisponible donne son refus, sans bouton Appliquer', () => {
    const verdict = validateProposal(
      proposal({ available: false, refusal: '.env est un fichier protégé' }),
      context()
    )
    assert.deepEqual(verdict, { ok: false, reason: '.env est un fichier protégé' })
  })
})

// --------------------------------------------------------------------------
// Application
// --------------------------------------------------------------------------

describe('remédiation assistée — application bornée', () => {
  it('rien n’est écrit tant que l’application n’est pas demandée', () => {
    const document = new FakeDocument(FILE)
    const built = buildFixRequest(finding(), document.getText(), 'backend/config.py', 'python')
    assert.equal(built.ok, true)
    validateProposal(proposal(), context())
    proposedText(document.getText(), proposal())

    assert.equal(document.writes, 0)
    assert.equal(document.saves, 0)
    assert.equal(document.getText(), FILE)
  })

  it('sans confirmation, rien n’est écrit', async () => {
    for (const confirm of [
      async () => false,
      async () => {
        throw new Error('fenêtre fermée')
      },
    ]) {
      const document = new FakeDocument(FILE)
      let confirmedHook = false

      const outcome = await confirmAndApply(confirm, document, proposal(), contentHash(FILE), () => {
        confirmedHook = true
      })

      assert.deepEqual(outcome, { status: 'not_confirmed' })
      assert.equal(confirmedHook, false)
      assert.equal(document.writes, 0)
      assert.equal(document.saves, 0)
      assert.equal(document.getText(), FILE)
    }
  })

  it('la confirmation est demandée avant toute écriture', async () => {
    const document = new FakeDocument(FILE)
    let writesWhenAsked = -1

    const outcome = await confirmAndApply(
      async () => {
        writesWhenAsked = document.writes
        return true
      },
      document,
      proposal(),
      contentHash(FILE)
    )

    assert.equal(writesWhenAsked, 0)
    assert.deepEqual(outcome, { status: 'applied' })
  })

  it('applique la seule plage proposée et enregistre', async () => {
    const document = new FakeDocument(FILE)

    const outcome = await applyBoundedFix(document, proposal(), contentHash(FILE))

    assert.deepEqual(outcome, { status: 'applied' })
    assert.equal(document.saves, 1)
    const lines = splitLines(document.getText()).lines
    assert.equal(lines[6], '    OPENAI_KEY = os.environ["OPENAI_API_KEY"]')
    // Tout le reste est intact.
    assert.deepEqual(
      lines.filter((_, index) => index !== 6),
      splitLines(FILE).lines.filter((_, index) => index !== 6)
    )
    assert.ok(!document.getText().includes(SECRET_VALUE))
  })

  it('conserve les fins de ligne CRLF', async () => {
    const crlf = FILE.split('\n').join('\r\n')
    const document = new FakeDocument(crlf)

    await applyBoundedFix(document, proposal({ base_content_hash: contentHash(crlf) }), contentHash(crlf))

    assert.equal(document.getText().split('\r\n').length, crlf.split('\r\n').length)
    assert.ok(!/[^\r]\n/.test(document.getText()))
  })

  it('refuse d’appliquer à un fichier modifié depuis la proposition', async () => {
    const document = new FakeDocument(FILE.replace('gpt-4o-mini', 'gpt-4o'))

    const outcome = await applyBoundedFix(document, proposal(), contentHash(FILE))

    assert.equal(outcome.status, 'stale')
    assert.equal(document.writes, 0)
  })

  it('refuse d’appliquer à un fichier aux modifications non enregistrées', async () => {
    const document = new FakeDocument(FILE)
    document.dirty = true

    const outcome = await applyBoundedFix(document, proposal(), contentHash(FILE))

    assert.equal(outcome.status, 'stale')
    assert.equal(document.writes, 0)
  })

  it('un éditeur qui refuse la modification laisse le fichier intact', async () => {
    for (const failure of ['false', 'throw'] as const) {
      const document = new FakeDocument(FILE)
      document.failReplace = failure

      const outcome = await applyBoundedFix(document, proposal(), contentHash(FILE))

      assert.equal(outcome.status, 'failed', failure)
      assert.equal(outcome.status === 'failed' && outcome.restored, true)
      assert.equal(document.getText(), FILE)
      assert.equal(document.saves, 0)
    }
  })

  it('un résultat inattendu est annulé avant tout enregistrement', async () => {
    const document = new FakeDocument(FILE)
    document.corrupt = true

    const outcome = await applyBoundedFix(document, proposal(), contentHash(FILE))

    assert.equal(outcome.status, 'failed')
    assert.equal(document.getText(), FILE)
    assert.equal(document.saves, 0)
  })

  it('un enregistrement refusé ramène le document à l’original', async () => {
    const document = new FakeDocument(FILE)
    document.failSave = true

    const outcome = await applyBoundedFix(document, proposal(), contentHash(FILE))

    assert.equal(outcome.status, 'failed')
    assert.equal(outcome.status === 'failed' && outcome.restored, true)
    assert.equal(document.getText(), FILE)
  })

  it('un retour arrière impossible est annoncé, jamais masqué', async () => {
    const document = new FakeDocument(FILE)
    document.failSave = true
    document.failRestore = true

    const outcome = await applyBoundedFix(document, proposal(), contentHash(FILE))

    assert.equal(outcome.status, 'failed')
    assert.equal(outcome.status === 'failed' && outcome.restored, false)
  })
})

// --------------------------------------------------------------------------
// Vérification par les moteurs
// --------------------------------------------------------------------------

describe('remédiation assistée — vérification', () => {
  it('appliquer ne retire pas le finding : seule une nouvelle analyse le fait', async () => {
    const store = new FindingsStore()
    store.replaceProjectFindings([finding()])
    const before = JSON.stringify(store.all())

    await applyBoundedFix(new FakeDocument(FILE), proposal(), contentHash(FILE))

    // Aucune décision, aucune suppression : le registre est intact, la
    // gravité aussi, et le finding est toujours « détecté ».
    assert.equal(JSON.stringify(store.all()), before)
    assert.equal(store.get('finding-1')?.severity, 'CRITICAL')
    assert.equal(stillDetected(finding(), store.all()), true)
  })

  it('le moteur ne produit plus le finding : résolu', () => {
    const store = new FindingsStore()
    store.replaceProjectFindings([finding()])
    store.replaceProjectFindings([])

    assert.equal(stillDetected(finding(), store.all()), false)
  })

  it('le même secret retrouvé ailleurs dans le fichier reste « présent »', () => {
    const moved = finding({
      finding_uid: 'nouvel-identifiant',
      location: { line_start: 12, line_end: 12, column_start: 0, column_end: 0, snippet: '' },
    })
    assert.equal(stillDetected(finding(), [moved]), true)
  })

  it('un finding d’un autre fichier, refermé, ou d’un autre moteur ne compte pas', () => {
    assert.equal(stillDetected(finding(), [finding({ file_path: 'other.py' })]), false)
    assert.equal(stillDetected(finding(), [finding({ status: 'dismissed' })]), false)
    assert.equal(
      stillDetected(finding(), [finding({ detection_engine: undefined, rule_id: 'secret-scanner' })]),
      false
    )
  })

  it('un finding de code est retrouvé par sa règle', () => {
    const code = finding({ detection_engine: undefined, rule_id: 'PY-TLS-001', scan_uid: 'scan-1' })
    assert.equal(stillDetected(code, [{ ...code, finding_uid: 'scan-2-x' }]), true)
    assert.equal(stillDetected(code, [{ ...code, rule_id: 'PY-OTHER' }]), false)
  })
})

// --------------------------------------------------------------------------
// Fenêtre de l'assistant
// --------------------------------------------------------------------------

function fixModel(state: FixPanelState): AiPanelModel {
  return {
    ...initialModel({ kind: 'fix', findingId: 'finding-1', findingTitle: 'Titre' }),
    status: 'ready',
    fix: state,
  }
}

describe('remédiation assistée — aperçu', () => {
  it('montre fichier, plage, code actuel expurgé, proposition, et marque l’IA', () => {
    const html = buildAiPanelHtml(
      fixModel({
        stage: 'proposed',
        proposal: proposal(),
        currentLines: ['    OPENAI_KEY = "sk-proj-********"'],
      }),
      'n'
    )
    assert.match(html, /Généré par IA/)
    assert.match(html, /confirmation/)
    assert.match(html, /backend\/config\.py, ligne 7/)
    assert.match(html, /sk-proj-\*\*\*\*\*\*\*\*/)
    assert.ok(!html.includes(SECRET_VALUE))
    assert.match(html, /os\.environ\[&quot;OPENAI_API_KEY&quot;\]/)
    assert.match(html, /<span class="badge critical">CRITICAL<\/span>/)
    assert.match(html, /id="applyFix"/)
    assert.match(html, /id="cancelFix"/)
    assert.match(html, /id="showFixDiff"/)
    assert.match(html, /Révoquez la clé exposée/)
  })

  it('n’affiche aucun bouton Appliquer sans proposition validée', () => {
    for (const state of [
      { stage: 'loading' },
      { stage: 'refused', message: 'fichier protégé', manualSteps: ['Déplacer la valeur'] },
      { stage: 'rejected', message: 'La proposition écrivait une valeur de secret' },
      { stage: 'stale', proposal: proposal(), message: 'Le fichier a changé' },
      { stage: 'cancelled', proposal: proposal() },
      { stage: 'failed', proposal: proposal(), message: 'échec', restored: true },
      { stage: 'done', proposal: proposal(), verification: 'resolved' },
    ] as FixPanelState[]) {
      const html = buildAiPanelHtml(fixModel(state), 'n')
      assert.ok(!html.includes('id="applyFix"'), state.stage)
    }
  })

  it('un refus annonce la remédiation manuelle', () => {
    const html = buildAiPanelHtml(
      fixModel({ stage: 'refused', message: '.env est un fichier protégé', manualSteps: ['Retirer la valeur du dépôt'] }),
      'n'
    )
    assert.match(html, /Remédiation manuelle requise/)
    assert.match(html, /\.env est un fichier protégé/)
    assert.match(html, /Retirer la valeur du dépôt/)
    assert.match(html, /Rien n’a été modifié/)
  })

  it('le verdict affiché est celui des moteurs, jamais celui de l’IA', () => {
    const verdicts: [FixPanelState['verification'], RegExp][] = [
      ['resolved', /ne signalent plus ce problème/],
      ['still_present', /signalent toujours ce problème/],
      ['unverified', /n’a pas pu être menée/],
    ]
    for (const [verification, expected] of verdicts) {
      const html = buildAiPanelHtml(fixModel({ stage: 'done', proposal: proposal(), verification }), 'n')
      assert.match(html, expected)
      assert.match(html, /Aucune décision n’est enregistrée par l’IA/)
    }
  })

  it('un échec dit si le fichier a été restauré', () => {
    const restored = buildAiPanelHtml(fixModel({ stage: 'failed', proposal: proposal(), message: 'x', restored: true }), 'n')
    const lost = buildAiPanelHtml(fixModel({ stage: 'failed', proposal: proposal(), message: 'x', restored: false }), 'n')
    assert.match(restored, /restauré dans son état d’origine/)
    assert.match(lost, /n’a pas pu être restauré/)
  })

  it('un fichier modifié demande une nouvelle proposition', () => {
    const html = buildAiPanelHtml(fixModel({ stage: 'stale', proposal: proposal(), message: 'Le fichier a changé' }), 'n')
    assert.match(html, /nouvelle proposition/)
  })

  it('échappe le code proposé', () => {
    const html = buildAiPanelHtml(
      fixModel({ stage: 'proposed', proposal: proposal({ replacement_lines: ['<script>alert(1)</script>'] }) }),
      'n'
    )
    assert.ok(!html.includes('<script>alert(1)</script>'))
    assert.ok(html.includes('&lt;script&gt;'))
  })

  it('la page ne demande que des actions ; elle n’écrit rien', () => {
    assert.deepEqual(parsePanelMessage({ action: 'applyFix' }), { action: 'applyFix' })
    assert.deepEqual(parsePanelMessage({ action: 'cancelFix' }), { action: 'cancelFix' })
    assert.deepEqual(parsePanelMessage({ action: 'showFixDiff' }), { action: 'showFixDiff' })
    // Une page ne transmet ni contenu à écrire, ni décision.
    assert.deepEqual(parsePanelMessage({ action: 'applyFix', text: 'rm -rf' }), { action: 'applyFix' })
    assert.equal(parsePanelMessage({ action: 'markFixed' }), undefined)
    assert.equal(parsePanelMessage({ action: 'writeFile', text: 'x' }), undefined)
  })
})

describe('remédiation assistée — contrôleur', () => {
  const backend: SecurityAiBackend = {
    securityAiHealth: async () => {
      throw new Error('non utilisé')
    },
    analyzeFindingWithAi: async () => {
      throw new Error('non utilisé')
    },
    summarizeFindingsWithAi: async () => {
      throw new Error('non utilisé')
    },
    askSecurityChat: async (_uid, request) => ({
      project_uid: 'projet-a',
      ai_generated: true,
      disclaimer: 'd',
      model: 'm',
      answered_at: '',
      question: request.question,
      answer: `vu : ${request.finding_id}`,
      insufficient_context: false,
      missing_information: [],
      related_concepts: [],
      findings_considered: 1,
      findings_available: 1,
      truncated: false,
      project_context_available: true,
      history_turns_used: 0,
    }),
  }

  it('suit les étapes du correctif affiché', () => {
    const controller = new SecurityAiController({ backend, projectUid: () => 'projet-a' })
    controller.showFix('finding-1', 'Titre', { stage: 'loading' })
    controller.updateFix('finding-1', { stage: 'proposed', proposal: proposal() })

    assert.equal(controller.model.view.kind, 'fix')
    assert.equal(controller.model.fix?.stage, 'proposed')
  })

  it('ignore une mise à jour destinée à un autre finding', () => {
    const controller = new SecurityAiController({ backend, projectUid: () => 'projet-a' })
    controller.showFix('finding-1', 'Titre', { stage: 'loading' })
    controller.updateFix('autre', { stage: 'proposed', proposal: proposal() })

    assert.equal(controller.model.fix?.stage, 'loading')
  })

  it('une question posée depuis un correctif porte son finding', async () => {
    const controller = new SecurityAiController({ backend, projectUid: () => 'projet-a' })
    controller.showFix('finding-1', 'Titre', { stage: 'proposed', proposal: proposal() })
    await controller.ask('Et l’import ?')

    assert.equal(controller.model.chat[0]?.response?.answer, 'vu : finding-1')
  })
})

describe('fiche de détail — Suggest Fix with AI', () => {
  it('n’apparaît que si la remédiation est annoncée, pour un finding ouvert', () => {
    assert.ok(!buildDetailHtml(finding(), 'n').includes('id="aiFix"'))
    assert.match(buildDetailHtml(finding(), 'n', { aiFixAvailable: true }), /<button id="aiFix"/)
    assert.ok(
      !buildDetailHtml(finding({ status: 'fixed' }), 'n', { aiFixAvailable: true }).includes('id="aiFix"')
    )
  })
})

describe('fenêtre de l’assistant — fermée pendant un correctif', () => {
  /**
   * Régression : le contrôleur survit à la fenêtre (réponse IA en vol,
   * correctif en attente). Une fois la fenêtre fermée, VS Code lève
   * « Webview is disposed » à toute écriture : « Annuler » échouait, et
   * « Appliquer » s'interrompait après la confirmation, sans rien écrire.
   *
   * `aiPanel.ts` dépend de `vscode` : il reçoit ici un double minimal dont
   * la webview se comporte comme la vraie une fois détruite.
   */
  it('une mise à jour après fermeture ne lève pas', () => {
    const fakeVscode = {
      ViewColumn: { Beside: -2 },
      commands: { executeCommand: async () => undefined },
      window: {
        createWebviewPanel: () => {
          let disposed = false
          const listeners: (() => void)[] = []
          const guard = () => {
            if (disposed) {
              throw new Error('Webview is disposed')
            }
          }
          return {
            webview: {
              set html(_value: string) {
                guard()
              },
              onDidReceiveMessage: () => ({ dispose() {} }),
            },
            set title(_value: string) {
              guard()
            },
            reveal() {},
            onDidDispose(listener: () => void) {
              listeners.push(listener)
              return { dispose() {} }
            },
            dispose() {
              disposed = true
              listeners.forEach((listener) => listener())
            },
          }
        },
      },
    }

    const loader = Module as unknown as {
      _load: (request: string, parent: unknown, isMain: boolean) => unknown
    }
    const original = loader._load
    loader._load = function (request, parent, isMain) {
      return request === 'vscode' ? fakeVscode : original.call(this, request, parent, isMain)
    }
    try {
      // Chargé après le double : `import` serait évalué avant lui.
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { SecurityAiPanel } = require('../src/ui/aiPanel') as typeof import('../src/ui/aiPanel')
      const controller = SecurityAiPanel.open({
        backend: {} as SecurityAiBackend,
        projectUid: () => 'projet-a',
      })
      controller.showFix('finding-1', 'Titre', { stage: 'proposed', proposal: proposal() })

      SecurityAiPanel.disposeCurrent()

      assert.doesNotThrow(() => controller.updateFix('finding-1', { stage: 'cancelled' }))
      assert.doesNotThrow(() => controller.updateFix('finding-1', { stage: 'applying' }))
      assert.equal(controller.model.fix?.stage, 'applying')
    } finally {
      loader._load = original
    }
  })
})
