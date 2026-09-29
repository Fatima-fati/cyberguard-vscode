/**
 * Tests de la lecture d'un diff et de l'attribution qui en découle.
 *
 * Ces deux modules répondent à la question qui donne son sens à la phase
 * 4 : *quelles lignes le développeur vient-il d'écrire, et lesquels de
 * ses problèmes viennent de là ?*
 *
 * Se tromper ici ne produit pas un plantage, mais quelque chose de pire :
 * un `push` bloqué pour un problème vieux de deux ans, ou un secret
 * ajouté à l'instant classé « préexistant ». Les deux se voient
 * seulement à l'usage — d'où ces tests.
 *
 * Aucun dépôt réel, aucune commande `git` : le diff est du texte, et
 * c'est exactement ce que l'API `vscode.git` rend.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  attributeFindings,
  attributeOne,
  emptySummary,
  severityOf,
  tally,
} from '../src/git/changeAttribution'
import {
  buildChangedLineIndex,
  intersectsRanges,
  parseUnifiedDiff,
  toRanges,
} from '../src/git/diffParser'
import {
  carriesCredentials,
  remoteHostOf,
  sanitizeRemoteUrl,
  toSafeRemote,
} from '../src/git/remoteUrl'
import type { SecurityFinding } from '../src/security/securityTypes'

// --------------------------------------------------------------------------
// Fabriques
// --------------------------------------------------------------------------

function finding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: 'sec-1',
    project_uid: 'proj-a',
    category: 'SECRET',
    severity: 'CRITICAL',
    severity_label: 'Critique',
    confidence: 'HIGH',
    confidence_label: 'Élevée',
    category_label: 'Secret exposé',
    title: "Clé d'API écrite en dur",
    description: 'Une clé apparaît dans le code source.',
    file: 'src/config.py',
    line_start: 12,
    line_end: 12,
    evidence: 'sk-proj-********',
    remediation: 'Révoquez cette clé.',
    references: ['CWE-798'],
    detection_engine: 'secret-scanner',
    status: 'open',
    status_label: 'Ouvert',
    created_at: '2026-09-28T10:00:00Z',
    ...overrides,
  }
}

// --------------------------------------------------------------------------
// Lecture du diff
// --------------------------------------------------------------------------

describe('parseUnifiedDiff — lignes ajoutées', () => {
  it('relève les numéros de ligne dans le fichier d’arrivée', () => {
    const diff = [
      'diff --git a/src/app.py b/src/app.py',
      'index 1111111..2222222 100644',
      '--- a/src/app.py',
      '+++ b/src/app.py',
      '@@ -10,4 +10,6 @@ def handler():',
      ' contexte',
      '+ajout un',
      '+ajout deux',
      ' contexte',
      '-retire',
      ' contexte',
    ].join('\n')

    const result = parseUnifiedDiff(diff)
    const file = result.files[0]

    assert.equal(result.files.length, 1)
    assert.equal(file?.path, 'src/app.py')
    assert.equal(file?.change, 'modified')
    // Le contexte occupe la ligne 10 ; les ajouts suivent en 11 et 12.
    assert.deepEqual(file?.addedRanges, [{ start: 11, end: 12 }])
    assert.equal(file?.addedCount, 2)
    assert.equal(file?.removedCount, 1)
  })

  it('numérote correctement après plusieurs sections', () => {
    const diff = [
      'diff --git a/src/app.py b/src/app.py',
      '--- a/src/app.py',
      '+++ b/src/app.py',
      '@@ -1,2 +1,3 @@',
      ' un',
      '+deux',
      ' trois',
      '@@ -40,2 +41,3 @@',
      ' quarante',
      '+quarante-et-un',
      ' quarante-deux',
    ].join('\n')

    const file = parseUnifiedDiff(diff).files[0]
    assert.deepEqual(file?.addedRanges, [
      { start: 2, end: 2 },
      { start: 42, end: 42 },
    ])
  })

  it('reconnaît un fichier ajouté', () => {
    const diff = [
      'diff --git a/src/nouveau.py b/src/nouveau.py',
      'new file mode 100644',
      '--- /dev/null',
      '+++ b/src/nouveau.py',
      '@@ -0,0 +1,3 @@',
      '+une',
      '+deux',
      '+trois',
    ].join('\n')

    const file = parseUnifiedDiff(diff).files[0]
    assert.equal(file?.change, 'added')
    assert.deepEqual(file?.addedRanges, [{ start: 1, end: 3 }])
  })

  it('reconnaît un fichier supprimé et ne lui attribue aucune ligne', () => {
    const diff = [
      'diff --git a/src/ancien.py b/src/ancien.py',
      'deleted file mode 100644',
      '--- a/src/ancien.py',
      '+++ /dev/null',
      '@@ -1,2 +0,0 @@',
      '-une',
      '-deux',
    ].join('\n')

    const file = parseUnifiedDiff(diff).files[0]
    assert.equal(file?.change, 'deleted')
    // Il n'y a plus de fichier d'arrivée où pointer.
    assert.deepEqual(file?.addedRanges, [])
    assert.equal(file?.removedCount, 2)
  })

  it('reconnaît un renommage', () => {
    const diff = [
      'diff --git a/src/vieux.py b/src/neuf.py',
      'similarity index 95%',
      'rename from src/vieux.py',
      'rename to src/neuf.py',
      '--- a/src/vieux.py',
      '+++ b/src/neuf.py',
      '@@ -1,2 +1,3 @@',
      ' une',
      '+deux',
    ].join('\n')

    const file = parseUnifiedDiff(diff).files[0]
    assert.equal(file?.change, 'renamed')
    assert.equal(file?.path, 'src/neuf.py')
    assert.equal(file?.previousPath, 'src/vieux.py')
  })

  it('marque un binaire sans lui inventer de lignes', () => {
    const diff = [
      'diff --git a/logo.png b/logo.png',
      'index 1111111..2222222 100644',
      'Binary files a/logo.png and b/logo.png differ',
    ].join('\n')

    const file = parseUnifiedDiff(diff).files[0]
    assert.equal(file?.binary, true)
    assert.equal(file?.addedCount, 0)
  })

  it('lit plusieurs fichiers d’un seul diff', () => {
    const diff = [
      'diff --git a/a.py b/a.py',
      '--- a/a.py',
      '+++ b/a.py',
      '@@ -1 +1,2 @@',
      ' un',
      '+deux',
      'diff --git a/b.py b/b.py',
      '--- a/b.py',
      '+++ b/b.py',
      '@@ -1 +1,2 @@',
      ' un',
      '+deux',
    ].join('\n')

    const result = parseUnifiedDiff(diff)
    assert.deepEqual(
      result.files.map((file) => file.path),
      ['a.py', 'b.py']
    )
    assert.equal(result.addedCount, 2)
  })

  it('ignore « \\ No newline at end of file »', () => {
    const diff = [
      'diff --git a/a.py b/a.py',
      '--- a/a.py',
      '+++ b/a.py',
      '@@ -1 +1 @@',
      '-ancien',
      '\\ No newline at end of file',
      '+nouveau',
      '\\ No newline at end of file',
    ].join('\n')

    const file = parseUnifiedDiff(diff).files[0]
    assert.deepEqual(file?.addedRanges, [{ start: 1, end: 1 }])
  })

  it('ne lève jamais sur une entrée vide ou absurde', () => {
    assert.deepEqual(parseUnifiedDiff('').files, [])
    // Un analyseur qui s'arrête à la première ligne surprenante perdrait
    // le changement entier : il produit un résultat partiel, jamais une
    // exception.
    assert.doesNotThrow(() => parseUnifiedDiff('n’importe quoi\n@@ cassé @@\n+x'))
  })

  it('normalise les chemins et retire les préfixes a/ et b/', () => {
    const diff = [
      'diff --git a/src/sous/dossier/app.py b/src/sous/dossier/app.py',
      '--- a/src/sous/dossier/app.py',
      '+++ b/src/sous/dossier/app.py',
      '@@ -1 +1,2 @@',
      ' un',
      '+deux',
    ].join('\n')

    assert.equal(parseUnifiedDiff(diff).files[0]?.path, 'src/sous/dossier/app.py')
  })
})

describe('toRanges / intersectsRanges', () => {
  it('fusionne des lignes contiguës', () => {
    assert.deepEqual(toRanges([3, 1, 2, 7, 8]), [
      { start: 1, end: 3 },
      { start: 7, end: 8 },
    ])
  })

  it('dédoublonne', () => {
    assert.deepEqual(toRanges([5, 5, 5]), [{ start: 5, end: 5 }])
  })

  it('rend une liste vide pour aucune ligne', () => {
    assert.deepEqual(toRanges([]), [])
  })

  it('détecte le recouvrement dans les deux sens', () => {
    const ranges = [{ start: 10, end: 20 }]
    assert.equal(intersectsRanges(ranges, 15, 15), true)
    assert.equal(intersectsRanges(ranges, 5, 12), true)
    assert.equal(intersectsRanges(ranges, 18, 30), true)
    assert.equal(intersectsRanges(ranges, 1, 9), false)
    assert.equal(intersectsRanges(ranges, 21, 30), false)
  })
})

// --------------------------------------------------------------------------
// Attribution
// --------------------------------------------------------------------------

describe('attributeFindings — introduit ou préexistant', () => {
  const diff = [
    'diff --git a/src/config.py b/src/config.py',
    '--- a/src/config.py',
    '+++ b/src/config.py',
    '@@ -10,3 +10,5 @@',
    ' contexte',
    '+ligne onze',
    '+ligne douze',
    ' contexte',
  ].join('\n')

  const index = buildChangedLineIndex(parseUnifiedDiff(diff).files)

  it('classe « introduit » un problème sur une ligne ajoutée', () => {
    const result = attributeOne(finding({ line_start: 11, line_end: 11 }), index)
    assert.equal(result.origin, 'introduced')
  })

  it('classe « préexistant » un problème du même fichier ailleurs', () => {
    // Même fichier, ligne non touchée : le développeur n'a pas causé ce
    // problème, et l'en rendre responsable ferait désactiver la
    // protection.
    const result = attributeOne(finding({ line_start: 40, line_end: 40 }), index)
    assert.equal(result.origin, 'pre-existing')
  })

  it('classe « préexistant » un problème d’un fichier non modifié', () => {
    const result = attributeOne(finding({ file: 'src/autre.py' }), index)
    assert.equal(result.origin, 'pre-existing')
    assert.match(result.reason, /non modifié/)
  })

  it('classe « introduit » tout ce que porte un fichier ajouté', () => {
    const added = buildChangedLineIndex(
      parseUnifiedDiff(
        [
          'diff --git a/src/neuf.py b/src/neuf.py',
          '--- /dev/null',
          '+++ b/src/neuf.py',
          '@@ -0,0 +1,2 @@',
          '+une',
          '+deux',
        ].join('\n')
      ).files
    )

    const result = attributeOne(
      finding({ file: 'src/neuf.py', line_start: 999, line_end: 999 }),
      added
    )
    assert.equal(result.origin, 'introduced')
    assert.match(result.reason, /ajouté/)
  })

  it('ne classe jamais « introduit » un problème d’un fichier supprimé', () => {
    const deleted = buildChangedLineIndex(
      parseUnifiedDiff(
        [
          'diff --git a/src/parti.py b/src/parti.py',
          '--- a/src/parti.py',
          '+++ /dev/null',
          '@@ -1,2 +0,0 @@',
          '-une',
          '-deux',
        ].join('\n')
      ).files
    )

    const result = attributeOne(finding({ file: 'src/parti.py' }), deleted)
    assert.equal(result.origin, 'pre-existing')
  })

  it('classe « préexistant » un finding sans fichier', () => {
    const result = attributeOne(finding({ file: null }), index)
    assert.equal(result.origin, 'pre-existing')
  })

  it('classe « préexistant » un finding sans ligne dans un fichier modifié', () => {
    // Une dépendance vulnérable déclarée dans un manifeste modifié : on
    // ne sait pas situer la ligne, donc on ne conclut pas à « introduit ».
    const result = attributeOne(finding({ line_start: 0, line_end: 0 }), index)
    assert.equal(result.origin, 'pre-existing')
  })

  it('tolère un chemin à séparateurs Windows', () => {
    const result = attributeOne(
      finding({ file: 'src\\config.py', line_start: 11, line_end: 11 }),
      index
    )
    assert.equal(result.origin, 'introduced')
  })

  it('sépare les deux familles et conserve le total', () => {
    const result = attributeFindings(
      [
        finding({ id: 'a', line_start: 11, line_end: 11 }),
        finding({ id: 'b', line_start: 50, line_end: 50 }),
        finding({ id: 'c', file: 'src/ailleurs.py' }),
      ],
      index
    )

    assert.equal(result.introduced.length, 1)
    assert.equal(result.preExisting.length, 2)
    assert.equal(result.all.length, 3)
    assert.equal(result.introduced[0]?.finding.id, 'a')
  })

  it('ne modifie jamais le finding reçu', () => {
    const original = finding({ line_start: 11, line_end: 11 })
    const snapshot = JSON.stringify(original)

    attributeOne(original, index)

    // L'attribution vit **à côté** du finding : c'est ce qui permet à la
    // vue et aux diagnostics de continuer sur le type qu'ils connaissent.
    assert.equal(JSON.stringify(original), snapshot)
  })
})

describe('tally et severityOf', () => {
  it('compte par gravité', () => {
    const counts = tally([
      { finding: finding({ severity: 'CRITICAL' }), origin: 'introduced', reason: '' },
      { finding: finding({ severity: 'HIGH' }), origin: 'introduced', reason: '' },
      { finding: finding({ severity: 'HIGH' }), origin: 'introduced', reason: '' },
      { finding: finding({ severity: 'LOW' }), origin: 'introduced', reason: '' },
    ])

    assert.deepEqual(counts, { critical: 1, high: 2, medium: 0, low: 1, total: 4 })
  })

  it('ramène une gravité inconnue à LOW', () => {
    assert.equal(
      severityOf(finding({ severity: 'BIZARRE' as never })),
      'LOW'
    )
  })
})

describe('emptySummary', () => {
  it('n’est jamais concluant par défaut', () => {
    // Un résumé vide ne doit **jamais** se lire « aucun problème
    // introduit » : c'est exactement la confusion que la phase s'interdit.
    assert.equal(emptySummary().conclusive, false)
    assert.equal(emptySummary().repository, false)
    assert.equal(emptySummary().introduced.total, 0)
  })
})

// --------------------------------------------------------------------------
// Métadonnées de remote
// --------------------------------------------------------------------------

describe('remoteUrl — aucune information d’identification ne survit', () => {
  it('extrait l’hôte d’une URL HTTPS', () => {
    assert.equal(remoteHostOf('https://github.com/org/depot.git'), 'github.com')
  })

  it('extrait l’hôte d’une forme SCP', () => {
    assert.equal(remoteHostOf('git@github.com:org/depot.git'), 'github.com')
  })

  it('n’expose jamais le jeton d’une URL qui en porte un', () => {
    const url = 'https://x-access-token:ghp_TRESSECRET123@github.com/org/depot.git'

    assert.equal(remoteHostOf(url), 'github.com')
    const sanitized = sanitizeRemoteUrl(url)
    assert.equal(sanitized, 'github.com/org/depot.git')
    assert.equal(sanitized?.includes('ghp_TRESSECRET123'), false)
    assert.equal(sanitized?.includes('x-access-token'), false)
  })

  it('retire un mot de passe simple', () => {
    const sanitized = sanitizeRemoteUrl('https://alice:motdepasse@gitlab.com/a/b.git')
    assert.equal(sanitized, 'gitlab.com/a/b.git')
    assert.equal(sanitized?.includes('motdepasse'), false)
  })

  it('retire une chaîne de requête, où un jeton tiendrait très bien', () => {
    const sanitized = sanitizeRemoteUrl('https://host.example/a/b.git?token=abcdef')
    assert.equal(sanitized?.includes('abcdef'), false)
  })

  it('renvoie null plutôt qu’une chaîne qu’il n’a pas su lire', () => {
    // Une URL qu'on ne sait pas analyser est précisément celle qu'il ne
    // faut pas afficher.
    assert.equal(remoteHostOf('n’importe quoi'), null)
    assert.equal(sanitizeRemoteUrl('n’importe quoi'), null)
    assert.equal(remoteHostOf(undefined), null)
    assert.equal(sanitizeRemoteUrl(null), null)
  })

  it('reconnaît une URL porteuse d’identifiants', () => {
    assert.equal(carriesCredentials('https://user:pass@host/a.git'), true)
    assert.equal(carriesCredentials('https://github.com/org/depot.git'), false)
    // `git@hôte:` est la forme SSH ordinaire, sans mot de passe.
    assert.equal(carriesCredentials('git@github.com:org/depot.git'), false)
  })

  it('réduit un remote à sa forme sûre', () => {
    const safe = toSafeRemote({
      name: 'origin',
      fetchUrl: 'https://token123@github.com/org/depot.git',
    })

    assert.equal(safe.name, 'origin')
    assert.equal(safe.host, 'github.com')
    assert.equal(safe.url?.includes('token123'), false)
  })

  it('conserve le port, qui n’est pas un secret', () => {
    assert.equal(
      sanitizeRemoteUrl('https://git.interne.example:8443/org/depot.git'),
      'git.interne.example:8443/org/depot.git'
    )
  })
})
