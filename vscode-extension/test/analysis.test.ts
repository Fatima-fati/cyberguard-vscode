/**
 * Tests du filtrage des documents et de l'empreinte.
 *
 * Fonctions pures, sans dépendance à `vscode` : aucun réseau, aucun
 * backend, aucune clé.
 */

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'

import { contentHash, contentSize, shortHash } from '../src/analysis/contentHash'
import {
  isSourceDocument,
  pickScanTarget,
  type DocumentLike,
} from '../src/analysis/activeDocument'
import {
  GitignoreMatcher,
  MAX_CONTENT_BYTES,
  PLANNED_LANGUAGES,
  SUPPORTED_LANGUAGES,
  evaluate,
  type FilterInput,
} from '../src/analysis/documentFilter'
import { BackendClient, type CodeScanResult } from '../src/api/backendClient'

function input(overrides: Partial<FilterInput> = {}): FilterInput {
  return {
    fsPath: '/projet/src/users.py',
    relativePath: 'src/users.py',
    languageId: 'python',
    isUntitled: false,
    size: 120,
    ...overrides,
  }
}

/** Document tel que VS Code le présente à l'extension. */
function document(scheme: string, languageId: string): DocumentLike {
  return { uri: { scheme }, languageId }
}

/** Le panneau Output : un éditeur de texte, mais pas un fichier source. */
const OUTPUT_PANEL = document('output', 'Log')
const TEST_PY = document('file', 'python')

describe('contentHash', () => {
  it('calcule le SHA-256 attendu par le backend', () => {
    const content = 'def get_user(user_id):\n'
    const expected = createHash('sha256').update(content, 'utf8').digest('hex')

    assert.equal(contentHash(content), expected)
    assert.equal(contentHash(content).length, 64)
  })

  it('change dès que le contenu change', () => {
    assert.notEqual(contentHash('a = 1\n'), contentHash('a = 2\n'))
  })

  it('mesure la taille en octets, accents compris', () => {
    assert.equal(contentSize('abc'), 3)
    assert.equal(contentSize('é'), 2)
  })

  it('tronque l’empreinte pour les journaux', () => {
    assert.equal(shortHash('0'.repeat(64)).length, 12)
  })
})

describe('documentFilter — fichiers sensibles', () => {
  const sensitives = [
    '.env',
    '.env.local',
    'certs/server.pem',
    'certs/server.key',
    'keys/id_rsa',
    'app.p12',
    '.npmrc',
  ]

  for (const relativePath of sensitives) {
    it(`refuse ${relativePath} et le marque sensible`, () => {
      const decision = evaluate(input({ relativePath, languageId: 'python' }))

      assert.equal(decision.accepted, false)
      if (!decision.accepted) {
        assert.equal(decision.sensitive, true)
        assert.match(decision.reason, /sensible/)
      }
    })
  }

  it('applique la règle de sécurité avant celle du langage', () => {
    // Même avec un langage pris en charge, un .env ne part jamais.
    const decision = evaluate(input({ relativePath: '.env', languageId: 'python' }))
    assert.equal(decision.accepted, false)
  })
})

describe('documentFilter — exclusions et pertinence', () => {
  const excluded = [
    'node_modules/pkg/index.js',
    'dist/bundle.js',
    'build/app.js',
    '.git/config',
    '.venv/lib/mod.py',
    '__pycache__/mod.py',
    'vendor/lib.php',
  ]

  for (const relativePath of excluded) {
    it(`ignore ${relativePath}`, () => {
      const decision = evaluate(input({ relativePath, languageId: 'javascript' }))
      assert.equal(decision.accepted, false)
    })
  }

  it('refuse un document non enregistré', () => {
    const decision = evaluate(input({ isUntitled: true }))
    assert.equal(decision.accepted, false)
    if (!decision.accepted) {
      assert.match(decision.reason, /enregistré/)
    }
  })

  it('refuse un fichier vide', () => {
    const decision = evaluate(input({ size: 0 }))
    assert.equal(decision.accepted, false)
  })

  it('refuse un fichier trop volumineux', () => {
    const decision = evaluate(input({ size: MAX_CONTENT_BYTES + 1 }))
    assert.equal(decision.accepted, false)
    if (!decision.accepted) {
      assert.match(decision.reason, /volumineux/)
    }
  })

  it('refuse un langage non pris en charge', () => {
    const decision = evaluate(input({ languageId: 'markdown', relativePath: 'a.md' }))
    assert.equal(decision.accepted, false)
    if (!decision.accepted) {
      assert.equal(decision.sensitive, false)
      assert.match(decision.reason, /markdown/)
    }
  })
})

describe('documentFilter — langages', () => {
  const expected: Array<[string, string]> = [
    ['python', 'python'],
    ['javascript', 'javascript'],
    ['javascriptreact', 'javascript'],
    ['typescript', 'typescript'],
    ['typescriptreact', 'typescript'],
    ['php', 'php'],
    ['java', 'java'],
  ]

  for (const [languageId, sent] of expected) {
    it(`accepte ${languageId} et l'envoie comme « ${sent} »`, () => {
      const decision = evaluate(input({ languageId, relativePath: `src/fichier` }))
      assert.equal(decision.accepted, true)
      if (decision.accepted) {
        assert.equal(decision.language, sent)
      }
    })
  }

  it('garde les langages prévus hors du périmètre actuel', () => {
    for (const language of PLANNED_LANGUAGES) {
      assert.ok(
        !(language in SUPPORTED_LANGUAGES),
        `${language} ne doit pas encore être analysé`
      )
    }
  })
})

describe('documentFilter — .gitignore', () => {
  it('ne bloque rien quand aucun .gitignore n’est chargé', () => {
    const matcher = GitignoreMatcher.empty()
    assert.equal(matcher.ignores('src/users.py'), false)
  })

  it('reste vide si le dossier n’existe pas', () => {
    const matcher = GitignoreMatcher.load('/dossier/absent/xyz')
    assert.equal(matcher.ignores('src/users.py'), false)
  })
})

describe('activeDocument — choix du document analysé', () => {
  it('retient l’éditeur actif quand il montre un fichier source', () => {
    assert.equal(pickScanTarget(TEST_PY, [TEST_PY]), TEST_PY)
  })

  it('ignore le panneau Output et retombe sur le fichier visible', () => {
    // Le cas du bug : un clic dans le canal « Wazuh Security » avant
    // d'ouvrir la palette suffisait à faire analyser un document `Log`.
    const chosen = pickScanTarget(OUTPUT_PANEL, [OUTPUT_PANEL, TEST_PY])

    assert.equal(chosen, TEST_PY)
    assert.equal(chosen?.languageId, 'python')
  })

  it('ne renvoie rien quand aucun fichier source n’est à l’écran', () => {
    assert.equal(pickScanTarget(OUTPUT_PANEL, [OUTPUT_PANEL]), undefined)
    assert.equal(pickScanTarget(undefined, []), undefined)
  })

  it('reconnaît les schémas qui ne sont pas des fichiers source', () => {
    assert.equal(isSourceDocument(TEST_PY), true)
    assert.equal(isSourceDocument(OUTPUT_PANEL), false)
    assert.equal(isSourceDocument(document('extension-output', 'Log')), false)
    assert.equal(isSourceDocument(document('debug', 'Log')), false)
    assert.equal(isSourceDocument(undefined), false)
  })

  it('garde un vrai fichier .log, refusé plus loin avec son message', () => {
    // `log` en minuscules est un fichier ouvert par l'utilisateur, pas un
    // canal de sortie : il reste le document visé, et c'est le filtre qui
    // annonce que le langage n'est pas pris en charge.
    const logFile = document('file', 'log')
    assert.equal(pickScanTarget(logFile, [logFile]), logFile)

    const decision = evaluate(input({ languageId: 'log', relativePath: 'app.log' }))
    assert.equal(decision.accepted, false)
    if (!decision.accepted) {
      assert.match(decision.reason, /n'est pas encore pris en charge/)
    }
  })
})

describe('documentFilter — le langage du panneau Output', () => {
  it('refuse « Log » avec un message explicite', () => {
    const decision = evaluate(input({ languageId: 'Log', relativePath: 'sortie' }))

    assert.equal(decision.accepted, false)
    if (!decision.accepted) {
      assert.equal(decision.sensitive, false)
      assert.match(decision.reason, /Log/)
      assert.match(decision.reason, /n'est pas encore pris en charge/)
    }
  })

  it('ne se rabat sur aucun langage par défaut', () => {
    for (const languageId of ['', 'plaintext', 'markdown']) {
      const decision = evaluate(input({ languageId }))
      assert.equal(decision.accepted, false, `${languageId} ne doit pas être accepté`)
    }
  })

  it('ne remonte pas une valeur héritée du prototype', () => {
    const decision = evaluate(input({ languageId: 'constructor' }))
    assert.equal(decision.accepted, false)
  })
})

describe('chaîne complète — test.py part en python', () => {
  const realFetch = globalThis.fetch

  afterEach(() => {
    ;(globalThis as { fetch: unknown }).fetch = realFetch
  })

  it('résout le document, le langage, puis l’envoie au backend', async () => {
    const chosen = pickScanTarget(OUTPUT_PANEL, [OUTPUT_PANEL, TEST_PY])
    assert.ok(chosen)

    const content =
      `query = "SELECT * FROM users WHERE username = '" + username + "'"` + '\n'
    const decision = evaluate({
      fsPath: '/projet/test.py',
      relativePath: 'test.py',
      languageId: chosen.languageId,
      isUntitled: false,
      size: contentSize(content),
    })

    assert.equal(decision.accepted, true)
    assert.ok(decision.accepted && decision.language === 'python')

    let payload: Record<string, unknown> = {}
    ;(globalThis as { fetch: unknown }).fetch = async (
      _input: unknown,
      init?: RequestInit
    ) => {
      payload = JSON.parse(String(init?.body))
      return new Response(
        JSON.stringify({
          scan_uid: 'abc',
          file_path: 'test.py',
          findings: [],
          findings_count: 0,
          analysis_status: 'analyzed',
          cached: false,
        } satisfies Partial<CodeScanResult>),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    }

    const client = new BackendClient({ baseUrl: 'http://127.0.0.1:8000' })
    await client.scan({
      file_path: 'test.py',
      language: decision.accepted ? decision.language : '',
      content,
      content_hash: contentHash(content),
      workspace: 'projet',
      project_uid: null,
      ai_enrichment: false,
    })

    assert.equal(payload.language, 'python')
    assert.equal(payload.file_path, 'test.py')
  })
})
