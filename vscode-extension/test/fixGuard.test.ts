/**
 * Tests des garde-fous de la correction automatique.
 *
 * Ce sont les règles qui décident si l'extension écrit ou non dans le
 * fichier de quelqu'un : elles méritent d'être vérifiées une par une,
 * sans éditeur, sans réseau et sans backend.
 *
 * Chaque test décrit une situation où **il ne faut pas écrire**, ou la
 * seule où il le faut.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import type { CodeFixProposal } from '../src/api/backendClient'
import {
  validateFix,
  validateTarget,
  type DocumentState,
  type FixTarget,
} from '../src/analysis/fixGuard'
import { FR } from '../src/i18n/fr'

const ORIGINAL = 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)'
const PATCHED = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'

function target(overrides: Partial<FixTarget> = {}): FixTarget {
  return { status: 'open', line: 10, ...overrides }
}

function state(overrides: Partial<DocumentState> = {}): DocumentState {
  return {
    scheme: 'file',
    inWorkspace: true,
    lineCount: 40,
    currentLineText: ORIGINAL,
    currentHash: 'hash-analyse',
    analyzedHash: 'hash-analyse',
    ...overrides,
  }
}

function proposal(overrides: Partial<CodeFixProposal> = {}): CodeFixProposal {
  return {
    finding_uid: 'uid-1',
    available: true,
    original_line: ORIGINAL,
    replacement_line: PATCHED,
    explanation: 'Requête paramétrée',
    diff: null,
    blockers: [],
    manual_steps: [],
    line: 10,
    file_path: 'users.py',
    applies_automatically: false,
    ...overrides,
  }
}

/** Raccourci de lecture : le verdict est-il un refus, et lequel ? */
function refusal(verdict: ReturnType<typeof validateTarget>): {
  reason: string
  fileChanged: boolean
} {
  assert.equal(verdict.ok, false, 'un refus était attendu')
  if (verdict.ok) {
    throw new Error('inatteignable')
  }
  return { reason: verdict.reason, fileChanged: verdict.fileChanged }
}

describe('validateTarget — état du document', () => {
  it('accepte un fichier local, dans le workspace, inchangé', () => {
    const verdict = validateTarget(target(), state())

    assert.equal(verdict.ok, true)
    if (verdict.ok) {
      assert.equal(verdict.line, 10)
      assert.equal(verdict.replacement, ORIGINAL)
    }
  })

  it('refuse un document qui n’est pas un fichier local', () => {
    // Aucune écriture sur un fichier distant, un dépôt virtuel ou un
    // document en lecture seule fourni par une autre extension.
    for (const scheme of ['untitled', 'vscode-remote', 'git', 'ssh']) {
      const verdict = validateTarget(target(), state({ scheme }))
      assert.equal(refusal(verdict).reason, FR.fix.notLocalFile)
      assert.equal(refusal(verdict).fileChanged, false)
    }
  })

  it('refuse un fichier étranger au workspace ouvert', () => {
    const verdict = validateTarget(target(), state({ inWorkspace: false }))
    assert.equal(refusal(verdict).reason, FR.fix.outsideWorkspace)
  })

  it('refuse un finding qui n’est plus ouvert', () => {
    for (const status of ['dismissed', 'fixed']) {
      const verdict = validateTarget(target({ status }), state())
      assert.equal(refusal(verdict).reason, FR.fix.notOpen)
    }
  })

  it('refuse quand le contenu ne correspond plus à celui analysé', () => {
    const verdict = validateTarget(
      target(),
      state({ currentHash: 'hash-modifie', analyzedHash: 'hash-analyse' })
    )

    const { reason, fileChanged } = refusal(verdict)
    assert.equal(fileChanged, true)
    assert.equal(reason, FR.fix.fileChanged)
  })

  it('affiche le message de dérive au mot près', () => {
    // Formulation imposée : elle ne doit pas dériver au fil des retouches.
    assert.equal(
      FR.fix.fileChanged,
      "Le fichier a changé depuis l'analyse. Veuillez relancer l'analyse."
    )
  })

  it('procède quand l’empreinte analysée est inconnue', () => {
    // Sans empreinte de référence, ce contrôle ne peut rien conclure : les
    // suivants — ligne d'origine, cohérence — restent en place.
    const verdict = validateTarget(target(), state({ analyzedHash: undefined }))
    assert.equal(verdict.ok, true)
  })

  it('refuse une ligne sortie des limites du document', () => {
    for (const line of [0, -1, 41, 999]) {
      const verdict = validateTarget(target({ line }), state({ lineCount: 40 }))
      assert.equal(refusal(verdict).fileChanged, true)
    }
  })

  it('refuse quand la ligne visée n’existe plus', () => {
    const verdict = validateTarget(target(), state({ currentLineText: undefined }))
    assert.equal(refusal(verdict).fileChanged, true)
  })
})

describe('validateFix — proposition du backend', () => {
  it('accepte une proposition cohérente sur une ligne intacte', () => {
    const verdict = validateFix(target(), proposal(), state())

    assert.equal(verdict.ok, true)
    if (verdict.ok) {
      assert.equal(verdict.replacement, PATCHED)
      assert.equal(verdict.line, 10)
    }
  })

  it('rejoue les contrôles d’état avant ceux de la proposition', () => {
    // Une proposition parfaite ne rattrape pas un fichier qui a bougé.
    const verdict = validateFix(
      target(),
      proposal(),
      state({ currentHash: 'autre-chose' })
    )
    assert.equal(refusal(verdict).reason, FR.fix.fileChanged)
  })

  it('refuse une proposition indisponible, en reprenant le motif du backend', () => {
    const verdict = validateFix(
      target(),
      proposal({
        available: false,
        replacement_line: null,
        blockers: ['Aucune correction automatique sûre pour cette règle.'],
      }),
      state()
    )

    assert.equal(
      refusal(verdict).reason,
      'Aucune correction automatique sûre pour cette règle.'
    )
    assert.equal(refusal(verdict).fileChanged, false)
  })

  it('refuse une proposition sans remplacement, même annoncée disponible', () => {
    const verdict = validateFix(
      target(),
      proposal({ available: true, replacement_line: null, blockers: [] }),
      state()
    )
    assert.equal(refusal(verdict).reason, FR.actions.fixUnavailable)
  })

  it('refuse si la ligne a changé pendant la confirmation', () => {
    // Le cas critique : la proposition a été calculée sur une ligne, et
    // l'utilisateur a modifié le fichier pendant que la modale était
    // ouverte. Rien ne doit être écrasé.
    const verdict = validateFix(
      target(),
      proposal({ original_line: ORIGINAL }),
      state({ currentLineText: 'cursor.execute(requete_deja_corrigee)' })
    )

    assert.equal(refusal(verdict).fileChanged, true)
    assert.equal(refusal(verdict).reason, FR.fix.fileChanged)
  })

  it('distingue une différence d’indentation seule', () => {
    // Le backend compare en ignorant les espaces de bord ; ici on compare
    // au caractère près, parce que c'est ce texte exact qui sera remplacé.
    const verdict = validateFix(
      target(),
      proposal({ original_line: ORIGINAL }),
      state({ currentLineText: `    ${ORIGINAL}` })
    )
    assert.equal(refusal(verdict).fileChanged, true)
  })

  it('refuse un remplacement multiligne', () => {
    for (const replacement of [
      'ligne1\nligne2',
      'ligne1\r\nligne2',
      'ligne1\rligne2',
    ]) {
      const verdict = validateFix(
        target(),
        proposal({ replacement_line: replacement }),
        state()
      )
      assert.equal(refusal(verdict).reason, FR.fix.multiline)
    }
  })

  it('refuse un remplacement identique à la ligne actuelle', () => {
    const verdict = validateFix(
      target(),
      proposal({ replacement_line: ORIGINAL }),
      state()
    )
    assert.equal(refusal(verdict).reason, FR.fix.noChange)
  })

  it('refuse un remplacement qui viderait une ligne non vide', () => {
    for (const replacement of ['', '   ', '\t']) {
      const verdict = validateFix(
        target(),
        proposal({ replacement_line: replacement }),
        state()
      )
      assert.equal(refusal(verdict).reason, FR.fix.emptyReplacement)
    }
  })

  it('accepte un remplacement quand la ligne d’origine n’est pas annoncée', () => {
    // `original_line` absent : le contrôle de dérive local ne s'applique
    // pas, mais la cohérence du remplacement reste vérifiée.
    const verdict = validateFix(
      target(),
      proposal({ original_line: null }),
      state()
    )
    assert.equal(verdict.ok, true)
  })

  it('n’accepte jamais une correction sur un finding refermé', () => {
    const verdict = validateFix(target({ status: 'fixed' }), proposal(), state())
    assert.equal(refusal(verdict).reason, FR.fix.notOpen)
  })
})
