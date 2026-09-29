/**
 * Tests de l'analyse des changements Git et de la protection avant push.
 *
 * Le dépôt temporaire
 * -------------------
 *
 * Les fichiers sont réels : un dossier temporaire est créé sur disque,
 * et le service les lit. Ce qui est simulé, c'est **l'API Git** — parce
 * que lancer `git` pour monter un dépôt de test contredirait précisément
 * ce que la phase 4 garantit, et parce que l'API `vscode.git` ne rend
 * de toute façon qu'une chaîne de diff.
 *
 * Le dernier test du fichier vérifie cette garantie sur le code source :
 * aucun module de `src/git/` n'importe `child_process`.
 */

import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readdirSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import * as path from 'node:path'
import { describe, it, after } from 'node:test'
import Module from 'node:module'

import { GIT_STATUS } from '../src/git/gitStatus'
import {
  GitSecurityService,
  dedupe,
  toSecurityFinding,
} from '../src/git/gitSecurityService'
import type {
  GitWorkspace,
  RepositorySnapshot,
  WorkspaceChange,
} from '../src/git/gitWorkspace'
import {
  decidePrePush,
  isBlocking,
  normalizeMode,
} from '../src/git/prePushPolicy'
import type { AttributedFinding } from '../src/git/changeAttribution'
import { emptySummary } from '../src/git/changeAttribution'
import type { SecurityFinding } from '../src/security/securityTypes'

// --------------------------------------------------------------------------
// Dépôt temporaire
// --------------------------------------------------------------------------

const created: string[] = []

after(() => {
  for (const directory of created) {
    try {
      rmSync(directory, { recursive: true, force: true })
    } catch {
      // Le nettoyage n'est pas l'objet du test.
    }
  }
})

/** Crée un dossier de projet temporaire, avec ses fichiers. */
function temporaryRepository(files: Record<string, string>): string {
  const root = mkdtempSync(path.join(tmpdir(), 'wazuh-git-'))
  created.push(root)

  // Le dossier `.git` est créé vide : sa seule présence suffit, et rien
  // dans la phase 4 ne le lit — tout passe par l'API.
  mkdirSync(path.join(root, '.git'), { recursive: true })

  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(root, relative)
    mkdirSync(path.dirname(target), { recursive: true })
    writeFileSync(target, content, 'utf8')
  }

  return root
}

/** `GitWorkspace` adossé au dossier temporaire, avec un diff fourni. */
function workspaceFor(
  root: string | undefined,
  snapshot: Partial<RepositorySnapshot> & { diffText?: string } | undefined
): GitWorkspace & { reads: string[] } {
  const reads: string[] = []

  return {
    reads,
    root: () => root,
    async snapshot(): Promise<RepositorySnapshot | undefined> {
      if (!snapshot) {
        return undefined
      }
      return {
        // `??` confondrait « non précisé » et « explicitement détaché » :
        // un dépôt en HEAD détaché porte bien `null`, et le test doit
        // pouvoir l'exprimer.
        branch: 'branch' in snapshot ? (snapshot.branch ?? null) : 'main',
        remoteHost: snapshot.remoteHost ?? 'github.com',
        changes: snapshot.changes ?? [],
        fingerprint: snapshot.fingerprint ?? 'main|abc|1|0|0',
        diff: snapshot.diff ?? (async () => snapshot.diffText ?? ''),
      }
    },
    async readFile(relative: string): Promise<string | undefined> {
      reads.push(relative)
      if (!root) {
        return undefined
      }
      try {
        return readFileSync(path.join(root, relative), 'utf8')
      } catch {
        return undefined
      }
    },
  }
}

const ALLOW_ALL = { ignores: () => false }

function service(
  workspace: GitWorkspace,
  options: {
    known?: readonly SecurityFinding[]
    maxChangedFiles?: number
    log?: (message: string) => void
    now?: () => number
  } = {}
): GitSecurityService {
  return new GitSecurityService({
    workspace,
    knownFindings: () => options.known ?? [],
    ignore: () => ALLOW_ALL,
    maxChangedFiles: () => options.maxChangedFiles ?? 50,
    log: options.log ?? (() => undefined),
    ...(options.now ? { now: options.now } : {}),
  })
}

function change(relative: string, status: number = GIT_STATUS.MODIFIED): WorkspaceChange {
  return { path: relative, status }
}

function finding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: 'sec-1',
    project_uid: 'proj-a',
    category: 'CODE',
    severity: 'HIGH',
    severity_label: 'Élevée',
    confidence: 'HIGH',
    confidence_label: 'Élevée',
    category_label: 'Code',
    title: 'Injection SQL',
    description: '',
    file: 'src/app.py',
    line_start: 5,
    line_end: 5,
    evidence: '',
    remediation: '',
    references: [],
    detection_engine: 'rules',
    status: 'open',
    status_label: 'Ouvert',
    created_at: '2026-09-28T10:00:00Z',
    ...overrides,
  }
}

/** Le secret utilisé par les tests. Jamais journalisé, par construction. */
const LEAKED_KEY = 'sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'

// --------------------------------------------------------------------------
// Aucun dépôt
// --------------------------------------------------------------------------

describe('GitSecurityService — aucun dépôt Git', () => {
  it('rend un résumé neutre et concluant, jamais une panne', async () => {
    const analysis = await service(workspaceFor('/tmp/projet', undefined)).analyze()

    assert.equal(analysis.summary.repository, false)
    // Concluant : on sait de source sûre qu'il n'y a rien à voir. C'est
    // différent d'une vérification qui a échoué.
    assert.equal(analysis.summary.conclusive, true)
    assert.equal(analysis.introduced.length, 0)
  })

  it('rend le même résultat sans dossier ouvert', async () => {
    const analysis = await service(workspaceFor(undefined, {})).analyze()
    assert.equal(analysis.summary.repository, false)
    assert.equal(analysis.summary.conclusive, true)
  })
})

// --------------------------------------------------------------------------
// Secret ajouté
// --------------------------------------------------------------------------

describe('GitSecurityService — secret ajouté par le changement', () => {
  it('repère un secret sur une ligne ajoutée et le dit « introduit »', async () => {
    const root = temporaryRepository({
      'src/config.py': ['DEBUG = True', `API_KEY = "${LEAKED_KEY}"`, 'PORT = 8000'].join(
        '\n'
      ),
    })

    const diff = [
      'diff --git a/src/config.py b/src/config.py',
      '--- a/src/config.py',
      '+++ b/src/config.py',
      '@@ -1,2 +1,3 @@',
      ' DEBUG = True',
      `+API_KEY = "${LEAKED_KEY}"`,
      ' PORT = 8000',
    ].join('\n')

    const analysis = await service(
      workspaceFor(root, { changes: [change('src/config.py')], diffText: diff })
    ).analyze()

    assert.equal(analysis.summary.conclusive, true)
    assert.equal(analysis.introduced.length, 1)
    assert.equal(analysis.introduced[0]?.finding.category, 'SECRET')
    assert.equal(analysis.introduced[0]?.finding.file, 'src/config.py')
  })

  it('repère un secret dans un fichier non suivi, absent du diff', async () => {
    const root = temporaryRepository({
      'settings.py': `TOKEN = "${LEAKED_KEY}"`,
    })

    // Git ne connaît pas encore ce fichier : aucun diff ne le mentionne.
    // C'est pourtant le cas le plus courant d'un secret qui fuit.
    const analysis = await service(
      workspaceFor(root, {
        changes: [change('settings.py', GIT_STATUS.UNTRACKED)],
        diffText: '',
      })
    ).analyze()

    assert.equal(analysis.introduced.length, 1)
    assert.equal(analysis.introduced[0]?.finding.file, 'settings.py')
  })

  it('n’ouvre jamais un fichier sensible, même modifié', async () => {
    const root = temporaryRepository({ '.env': `SECRET=${LEAKED_KEY}` })
    const workspace = workspaceFor(root, {
      changes: [change('.env')],
      diffText: '',
    })

    await service(workspace).analyze()

    // La règle de la phase 1 ne cède pas parce qu'un fichier vient de
    // bouger : un `.env` est signalé par son chemin, jamais lu.
    assert.equal(workspace.reads.includes('.env'), false)
  })
})

// --------------------------------------------------------------------------
// Changement sans danger
// --------------------------------------------------------------------------

describe('GitSecurityService — changement sans danger', () => {
  it('ne signale rien quand le changement est propre', async () => {
    const root = temporaryRepository({
      'src/app.py': ['def add(a, b):', '    return a + b', ''].join('\n'),
    })

    const diff = [
      'diff --git a/src/app.py b/src/app.py',
      '--- a/src/app.py',
      '+++ b/src/app.py',
      '@@ -1,1 +1,2 @@',
      ' def add(a, b):',
      '+    return a + b',
    ].join('\n')

    const analysis = await service(
      workspaceFor(root, { changes: [change('src/app.py')], diffText: diff })
    ).analyze()

    assert.equal(analysis.summary.conclusive, true)
    assert.equal(analysis.introduced.length, 0)
    assert.equal(analysis.summary.introduced.total, 0)
  })

  it('compte les lignes ajoutées et retirées', async () => {
    const root = temporaryRepository({ 'a.py': 'x = 1\n' })
    const diff = [
      'diff --git a/a.py b/a.py',
      '--- a/a.py',
      '+++ b/a.py',
      '@@ -1,2 +1,2 @@',
      '-ancien',
      '+x = 1',
      ' fin',
    ].join('\n')

    const analysis = await service(
      workspaceFor(root, { changes: [change('a.py')], diffText: diff })
    ).analyze()

    assert.equal(analysis.summary.addedLines, 1)
    assert.equal(analysis.summary.removedLines, 1)
  })
})

// --------------------------------------------------------------------------
// Préexistant contre introduit
// --------------------------------------------------------------------------

describe('GitSecurityService — préexistant contre introduit', () => {
  it('sépare les deux familles sur le même fichier', async () => {
    const root = temporaryRepository({
      'src/app.py': ['a', 'b', 'c', 'd', 'e', 'f'].join('\n'),
    })

    const diff = [
      'diff --git a/src/app.py b/src/app.py',
      '--- a/src/app.py',
      '+++ b/src/app.py',
      '@@ -4,2 +4,3 @@',
      ' d',
      '+e',
      ' f',
    ].join('\n')

    const analysis = await service(
      workspaceFor(root, { changes: [change('src/app.py')], diffText: diff }),
      {
        known: [
          // Sur la ligne ajoutée : introduit.
          finding({ id: 'neuf', line_start: 5, line_end: 5 }),
          // Ailleurs dans le même fichier : préexistant.
          finding({ id: 'vieux', line_start: 1, line_end: 1 }),
        ],
      }
    ).analyze()

    assert.deepEqual(
      analysis.introduced.map((item) => item.finding.id),
      ['neuf']
    )
    assert.deepEqual(
      analysis.preExisting.map((item) => item.finding.id),
      ['vieux']
    )
    assert.equal(analysis.summary.introduced.total, 1)
    assert.equal(analysis.summary.preExisting.total, 1)
  })

  it('n’écrase pas le statut d’un finding connu par un doublon local', async () => {
    const root = temporaryRepository({
      'src/config.py': `KEY = "${LEAKED_KEY}"`,
    })

    const known = finding({
      id: 'du-backend',
      category: 'SECRET',
      detection_engine: 'secret-scanner',
      file: 'src/config.py',
      line_start: 1,
      line_end: 1,
      title: "Clé d'API OpenAI",
      status: 'dismissed',
      status_label: 'Écarté',
    })

    const analysis = await service(
      workspaceFor(root, {
        changes: [change('src/config.py', GIT_STATUS.UNTRACKED)],
        diffText: '',
      }),
      { known: [known] }
    ).analyze()

    // Le finding du registre l'emporte : c'est lui qui porte la décision
    // de l'utilisateur.
    const same = analysis.attributed.filter(
      (item) => item.finding.file === 'src/config.py' && item.finding.line_start === 1
    )
    assert.equal(same.length, 1)
  })
})

// --------------------------------------------------------------------------
// Mode réduit
// --------------------------------------------------------------------------

describe('GitSecurityService — mode réduit', () => {
  it('borne l’analyse au-delà du plafond et l’annonce', async () => {
    const files: Record<string, string> = {}
    const changes: WorkspaceChange[] = []
    for (let index = 0; index < 60; index += 1) {
      const name = `src/file-${String(index).padStart(3, '0')}.py`
      files[name] = 'x = 1\n'
      changes.push(change(name))
    }

    const root = temporaryRepository(files)
    const analysis = await service(
      workspaceFor(root, { changes, diffText: '' }),
      { maxChangedFiles: 50 }
    ).analyze()

    assert.equal(analysis.summary.changedFiles, 60)
    assert.equal(analysis.summary.reduced, true)
    assert.equal(analysis.summary.analyzedFiles <= 50, true)
    // Une couverture partielle doit se voir, jamais se deviner.
    assert.match(analysis.summary.message, /partielle/i)
    // Et rester concluante : les fichiers analysés l'ont été correctement.
    assert.equal(analysis.summary.conclusive, true)
  })

  it('reste complet en dessous du plafond', async () => {
    const files: Record<string, string> = {}
    const changes: WorkspaceChange[] = []
    for (let index = 0; index < 10; index += 1) {
      files[`a-${index}.py`] = 'x = 1\n'
      changes.push(change(`a-${index}.py`))
    }

    const analysis = await service(
      workspaceFor(temporaryRepository(files), { changes, diffText: '' }),
      { maxChangedFiles: 50 }
    ).analyze()

    assert.equal(analysis.summary.reduced, false)
    assert.equal(analysis.summary.message, '')
  })

  it('retient toujours les mêmes fichiers d’une analyse à l’autre', async () => {
    const files: Record<string, string> = {}
    const changes: WorkspaceChange[] = []
    for (let index = 0; index < 20; index += 1) {
      files[`z-${index}.py`] = 'x = 1\n'
      changes.push(change(`z-${index}.py`))
    }
    const root = temporaryRepository(files)

    const first = workspaceFor(root, { changes, diffText: '' })
    const second = workspaceFor(root, {
      changes: [...changes].reverse(),
      diffText: '',
    })

    await service(first, { maxChangedFiles: 5 }).analyze()
    await service(second, { maxChangedFiles: 5 }).analyze()

    // L'ordre est stabilisé par le service : deux analyses du même état
    // produisent le même résumé, quel que soit l'ordre de l'API.
    assert.deepEqual(first.reads.sort(), second.reads.sort())
  })
})

// --------------------------------------------------------------------------
// Exclusions et cloisonnement
// --------------------------------------------------------------------------

describe('GitSecurityService — exclusions et cloisonnement', () => {
  it('ignore les dossiers exclus par la découverte', async () => {
    const root = temporaryRepository({
      'node_modules/pkg/index.js': `const k = "${LEAKED_KEY}"`,
      'dist/bundle.js': 'x',
    })

    const workspace = workspaceFor(root, {
      changes: [
        change('node_modules/pkg/index.js', GIT_STATUS.UNTRACKED),
        change('dist/bundle.js', GIT_STATUS.UNTRACKED),
      ],
      diffText: '',
    })

    const analysis = await service(workspace).analyze()

    assert.equal(analysis.summary.changedFiles, 0)
    assert.equal(workspace.reads.length, 0)
  })

  it('ignore un fichier que Git déclare ignoré', async () => {
    const root = temporaryRepository({ 'local.py': 'x = 1' })
    const analysis = await service(
      workspaceFor(root, {
        changes: [change('local.py', GIT_STATUS.IGNORED)],
        diffText: '',
      })
    ).analyze()

    assert.equal(analysis.summary.changedFiles, 0)
  })

  it('respecte le .gitignore du projet', async () => {
    const root = temporaryRepository({ 'build-out/app.js': 'x' })
    const analysis = await new GitSecurityService({
      workspace: workspaceFor(root, {
        changes: [change('build-out/app.js')],
        diffText: '',
      }),
      knownFindings: () => [],
      ignore: () => ({ ignores: (p: string) => p.startsWith('build-out/') }),
      maxChangedFiles: () => 50,
      log: () => undefined,
    }).analyze()

    assert.equal(analysis.summary.changedFiles, 0)
  })

  it('ne mélange pas deux projets : l’analyse est oubliée sur demande', async () => {
    const root = temporaryRepository({ 'a.py': 'x = 1' })
    const instance = service(
      workspaceFor(root, { changes: [change('a.py')], diffText: '' })
    )

    await instance.analyze()
    assert.equal(instance.summary().repository, true)

    instance.clear()

    // Après un changement de dossier, le résumé redevient neutre **et
    // non concluant** : il ne doit pas décrire l'ancien projet.
    assert.equal(instance.summary().repository, false)
    assert.equal(instance.summary().conclusive, false)
  })

  it('ne dédoublonne pas deux findings de fichiers différents', () => {
    const unique = dedupe([
      finding({ id: 'a', file: 'src/a.py' }),
      finding({ id: 'b', file: 'src/b.py' }),
    ])
    assert.equal(unique.length, 2)
  })
})

// --------------------------------------------------------------------------
// Changement de branche
// --------------------------------------------------------------------------

describe('GitSecurityService — changement de branche', () => {
  it('ne relance aucun parcours complet du projet', async () => {
    const files: Record<string, string> = { 'src/touche.py': 'x = 1\n' }
    // Cinquante fichiers que la branche n'a pas touchés : un parcours
    // complet les lirait tous.
    for (let index = 0; index < 50; index += 1) {
      files[`src/intact-${index}.py`] = 'y = 2\n'
    }
    const root = temporaryRepository(files)

    const workspace = workspaceFor(root, {
      branch: 'feature/nouvelle',
      changes: [change('src/touche.py')],
      diffText: [
        'diff --git a/src/touche.py b/src/touche.py',
        '--- a/src/touche.py',
        '+++ b/src/touche.py',
        '@@ -1 +1,2 @@',
        ' x = 1',
        '+z = 3',
      ].join('\n'),
    })

    const analysis = await service(workspace).analyze()

    assert.equal(analysis.summary.branch, 'feature/nouvelle')
    // Seul le fichier réellement modifié est lu. Changer de branche
    // touche parfois des milliers de fichiers : c'est précisément le
    // moment où un parcours complet coûterait le plus cher.
    assert.deepEqual(workspace.reads, ['src/touche.py'])
  })

  it('réutilise les findings déjà connus sans les recalculer', async () => {
    const root = temporaryRepository({ 'src/app.py': 'x = 1\n' })
    let calls = 0

    const instance = new GitSecurityService({
      workspace: workspaceFor(root, {
        branch: 'main',
        changes: [change('src/app.py')],
        diffText: '',
      }),
      knownFindings: () => {
        calls += 1
        return [finding({ id: 'connu' })]
      },
      ignore: () => ALLOW_ALL,
      maxChangedFiles: () => 50,
      log: () => undefined,
    })

    await instance.analyze()
    await instance.analyze()

    // Le registre est consulté, jamais reconstruit : la phase 4 classe
    // des findings, elle n'en produit pas.
    assert.equal(calls, 2)
    assert.equal(instance.summary().preExisting.total, 1)
  })

  it('suit la branche courante dans le résumé', async () => {
    const root = temporaryRepository({ 'a.py': 'x' })

    for (const branch of ['main', 'release/1.2', null]) {
      const analysis = await service(
        workspaceFor(root, { branch, changes: [], diffText: '' })
      ).analyze()
      assert.equal(analysis.summary.branch, branch)
    }
  })
})

// --------------------------------------------------------------------------
// Échec ouvert
// --------------------------------------------------------------------------

describe('GitSecurityService — échec ouvert', () => {
  it('rend un résumé non concluant quand le budget est dépassé', async () => {
    let clock = 0
    const analysis = await service(
      workspaceFor(temporaryRepository({ 'a.py': 'x' }), {
        changes: [change('a.py')],
        diffText: '',
      }),
      {
        // L'horloge saute au-delà de l'échéance dès le premier contrôle.
        now: () => (clock += 10_000),
      }
    ).analyze({ budgetMs: 100 })

    assert.equal(analysis.summary.conclusive, false)
    assert.equal(analysis.introduced.length, 0)
    // Le message dit pourquoi, plutôt que d'afficher un zéro rassurant.
    assert.notEqual(analysis.summary.message, '')
  })

  it('ne lève jamais quand le diff échoue', async () => {
    const workspace = workspaceFor(temporaryRepository({ 'a.py': 'x' }), {
      changes: [change('a.py')],
      diff: async () => {
        throw new Error('dépôt sans commit initial')
      },
    })

    const analysis = await service(workspace).analyze()
    // Un dépôt sans commit initial est un état normal : l'analyse
    // continue sur les fichiers non suivis.
    assert.equal(analysis.summary.repository, true)
  })

  it('ne lève jamais quand l’état du dépôt est illisible', async () => {
    const analysis = await service({
      root: () => '/tmp/projet',
      snapshot: async () => {
        throw new Error('API en panne')
      },
      readFile: async () => undefined,
    }).analyze()

    assert.equal(analysis.summary.conclusive, false)
  })
})

// --------------------------------------------------------------------------
// Politique avant push
// --------------------------------------------------------------------------

describe('decidePrePush — off / warn / block', () => {
  function attributed(
    severity: SecurityFinding['severity'],
    origin: AttributedFinding['origin'] = 'introduced'
  ): AttributedFinding {
    return { finding: finding({ severity }), origin, reason: '' }
  }

  const conclusive = emptySummary({ repository: true, conclusive: true })

  it('« off » laisse toujours passer', () => {
    const verdict = decidePrePush({
      mode: 'off',
      summary: conclusive,
      attributed: [attributed('CRITICAL')],
    })

    assert.equal(verdict.decision, 'allow')
    assert.equal(verdict.triggering.length, 0)
  })

  it('« warn » prévient sans bloquer', () => {
    const verdict = decidePrePush({
      mode: 'warn',
      summary: conclusive,
      attributed: [attributed('CRITICAL')],
    })

    assert.equal(verdict.decision, 'warn')
    assert.equal(verdict.triggering.length, 1)
    assert.equal(verdict.bypassAvailable, false)
  })

  it('« block » bloque, et propose TOUJOURS un contournement', () => {
    const verdict = decidePrePush({
      mode: 'block',
      summary: conclusive,
      attributed: [attributed('CRITICAL')],
    })

    assert.equal(verdict.decision, 'block')
    // Invariant du module : une protection sans échappatoire se
    // contourne par la ligne de commande, donc sans laisser de trace.
    assert.equal(verdict.bypassAvailable, true)
  })

  it('ne bloque jamais sur un problème préexistant', () => {
    for (const mode of ['warn', 'block'] as const) {
      const verdict = decidePrePush({
        mode,
        summary: conclusive,
        attributed: [attributed('CRITICAL', 'pre-existing')],
      })
      assert.equal(verdict.decision, 'allow', mode)
    }
  })

  it('ne bloque pas sur une gravité basse', () => {
    for (const severity of ['MEDIUM', 'LOW'] as const) {
      const verdict = decidePrePush({
        mode: 'block',
        summary: conclusive,
        attributed: [attributed(severity)],
      })
      assert.equal(verdict.decision, 'allow', severity)
    }
  })

  it('échoue ouvert quand l’analyse n’a pas conclu', () => {
    const verdict = decidePrePush({
      mode: 'block',
      summary: emptySummary({ repository: true, conclusive: false }),
      attributed: [attributed('CRITICAL')],
    })

    // Un agent qui empêche de pousser quand il tombe en panne est un
    // agent qu'on retire.
    assert.equal(verdict.decision, 'allow')
    assert.equal(verdict.degraded, true)
  })

  it('distingue « rien introduit » de « rien à signaler »', () => {
    const verdict = decidePrePush({
      mode: 'warn',
      summary: emptySummary({
        repository: true,
        conclusive: true,
        preExisting: { critical: 0, high: 2, medium: 0, low: 0, total: 2 },
      }),
      attributed: [attributed('HIGH', 'pre-existing')],
    })

    assert.equal(verdict.decision, 'allow')
    assert.match(verdict.reason, /préexistant/i)
  })

  it('normalise le réglage, et ne durcit jamais sur une valeur inconnue', () => {
    assert.equal(normalizeMode('off'), 'off')
    assert.equal(normalizeMode('block'), 'block')
    assert.equal(normalizeMode('warn'), 'warn')
    assert.equal(normalizeMode('BLOCK'), 'block')
    // Un réglage mal orthographié ne doit pas bloquer à l'insu de
    // l'utilisateur.
    assert.equal(normalizeMode('bloquer'), 'warn')
    assert.equal(normalizeMode(undefined), 'warn')
  })

  it('isBlocking ne retient que l’introduit et le grave', () => {
    assert.equal(isBlocking(attributed('CRITICAL')), true)
    assert.equal(isBlocking(attributed('HIGH')), true)
    assert.equal(isBlocking(attributed('MEDIUM')), false)
    assert.equal(isBlocking(attributed('CRITICAL', 'pre-existing')), false)
  })
})

// --------------------------------------------------------------------------
// Garanties de sécurité du module lui-même
// --------------------------------------------------------------------------

describe('Phase 4 — garanties sur le code lui-même', () => {
  const gitDirectory = path.join(__dirname, '..', 'src', 'git')

  /**
   * Code des modules Git, **commentaires retirés**.
   *
   * La garantie porte sur ce qui s'exécute, et ces fichiers expliquent
   * justement la règle en prose : scanner le texte brut ferait échouer le
   * test sur sa propre documentation.
   */
  function sources(): { name: string; text: string }[] {
    return readdirSync(gitDirectory)
      .filter((name) => name.endsWith('.ts'))
      .map((name) => ({
        name,
        text: readFileSync(path.join(gitDirectory, name), 'utf8')
          .replace(/\/\*[\s\S]*?\*\//g, '')
          .replace(/(^|[^:])\/\/.*$/gm, '$1'),
      }))
  }

  it('n’exécute aucune commande git', () => {
    // Lancer `git` reviendrait à exécuter un binaire choisi par le
    // `PATH`, dans un dossier qui vient d'être cloné, avec une
    // configuration que le dépôt lui-même peut fixer.
    for (const { name, text } of sources()) {
      assert.equal(/child_process/.test(text), false, `${name} importe child_process`)
      assert.equal(/\bexecSync\b|\bspawnSync\b|\bexecFile\b/.test(text), false, name)
      assert.equal(/createTerminal/.test(text), false, name)
    }
  })

  it('ne lit le dossier .git par aucun chemin détourné', () => {
    for (const { name, text } of sources()) {
      assert.equal(/['"`]\.git\//.test(text), false, `${name} lit dans .git/`)
    }
  })

  it('ne peut pas déclencher une découverte de projet', () => {
    // Garantie structurelle : changer de branche ne doit jamais relancer
    // un parcours complet. Le moyen le plus sûr de le tenir est que le
    // module Git n'ait aucun accès au service de découverte.
    for (const { name, text } of sources()) {
      assert.equal(/projectContext|discoverProject/.test(text), false, name)
    }
  })

  it('n’écrit aucun hook Git', () => {
    // « Protection avant push » laisse croire qu'un hook est installé.
    // Il ne l'est pas, et ce test empêche qu'il le devienne par
    // inadvertance.
    for (const { name, text } of sources()) {
      assert.equal(/hooks/.test(text), false, `${name} mentionne hooks dans du code`)
      assert.equal(/writeFile|appendFile|chmod/.test(text), false, name)
    }
  })
})

describe('Phase 4 — aucun secret dans le journal', () => {
  it('ne journalise jamais la valeur détectée', async () => {
    const root = temporaryRepository({
      'src/config.py': `API_KEY = "${LEAKED_KEY}"`,
    })

    const lines: string[] = []
    await service(
      workspaceFor(root, {
        changes: [change('src/config.py', GIT_STATUS.UNTRACKED)],
        diffText: '',
      }),
      { log: (message) => lines.push(message) }
    ).analyze()

    const journal = lines.join('\n')
    assert.equal(lines.length > 0, true, 'le journal doit dire quelque chose')
    assert.equal(journal.includes(LEAKED_KEY), false, 'la clé ne doit pas fuir')
    // Ni même sa partie distinctive.
    assert.equal(journal.includes('AbCdEfGh'), false)
  })

  it('ne journalise jamais l’URL du remote', async () => {
    const lines: string[] = []
    await service(
      workspaceFor(temporaryRepository({ 'a.py': 'x' }), {
        changes: [change('a.py')],
        diffText: '',
        remoteHost: 'github.com',
      }),
      { log: (message) => lines.push(message) }
    ).analyze()

    const journal = lines.join('\n')
    assert.equal(/ghp_|x-access-token|:\/\/[^\s]*@/.test(journal), false)
  })

  it('ne porte jamais la valeur d’un secret dans le finding converti', () => {
    const converted = toSecurityFinding({
      rule_id: 'openai-api-key',
      file_path: 'src/config.py',
      line: 3,
      column: 10,
      secret_type: 'openai_api_key',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      evidence_redacted: 'sk-proj-********',
      title: "Clé d'API OpenAI",
      description: '',
      remediation: '',
      references: [],
    })

    // L'identifiant est dérivé du chemin, de la ligne et du **type** :
    // rien ne permet de remonter à la valeur.
    assert.equal(converted.id.includes('sk-proj'), false)
    assert.equal(converted.evidence, 'sk-proj-********')
    assert.equal(converted.category, 'SECRET')
  })
})

describe('VsCodeGitWorkspace — diff de l’API Git réelle', () => {
  /**
   * Régression : l’adaptateur appelait `diffWithHEAD()` sans chemin. Dans
   * l’API de VS Code, cette forme renvoie la liste des changements
   * (`Change[]`), pas un diff : le diff était toujours vide, et un secret
   * ajouté à un fichier suivi était classé « préexistant » — la
   * vérification avant push ne l’arrêtait jamais.
   *
   * Le double reproduit les deux surcharges de l’API réelle.
   * `vscodeGitWorkspace.ts` dépend de `vscode` : il reçoit un double
   * minimal adossé au vrai disque.
   */
  const root = mkdtempSync(path.join(tmpdir(), 'git-api-'))
  mkdirSync(path.join(root, 'web'))
  writeFileSync(path.join(root, 'web', 'app.js'), "'use strict'\nmodule.exports = {}\nconst KEY = 1\n")
  after(() => rmSync(root, { recursive: true, force: true }))

  const calls: unknown[] = []
  const repository = {
    rootUri: { fsPath: root },
    state: {
      HEAD: { name: 'main', commit: 'abc' },
      indexChanges: [],
      workingTreeChanges: [
        { uri: { scheme: 'file', fsPath: path.join(root, 'web', 'app.js') }, status: GIT_STATUS.MODIFIED },
        { uri: { scheme: 'file', fsPath: path.join(root, '.env') }, status: GIT_STATUS.MODIFIED },
      ],
      mergeChanges: [],
      remotes: [],
    },
    // Surcharges de l’API réelle : sans chemin, des changements.
    diffWithHEAD: async (target?: string) => {
      calls.push(target)
      if (target === undefined) {
        return [{ uri: {}, status: GIT_STATUS.MODIFIED }]
      }
      return target.endsWith('app.js')
        ? 'diff --git a/web/app.js b/web/app.js\n--- a/web/app.js\n+++ b/web/app.js\n' +
            "@@ -1,2 +1,3 @@\n 'use strict'\n module.exports = {}\n+const KEY = 1\n"
        : ''
    },
    diffIndexWithHEAD: async (target?: string) => {
      calls.push(target)
      return target === undefined ? [] : ''
    },
  }

  function load() {
    const fakeVscode = {
      Uri: { file: (fsPath: string) => ({ fsPath }) },
      workspace: {
        fs: {
          stat: async (uri: { fsPath: string }) => ({ size: readFileSync(uri.fsPath).length }),
          readFile: async (uri: { fsPath: string }) => readFileSync(uri.fsPath),
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
      const { VsCodeGitWorkspace } = require('../src/git/vscodeGitWorkspace') as typeof import('../src/git/vscodeGitWorkspace')
      return new VsCodeGitWorkspace({
        workspaceRoot: () => root,
        resolveApi: async () => ({ repositories: [repository] }) as never,
      })
    } finally {
      loader._load = original
    }
  }

  it('demande le diff fichier par fichier, jamais la forme sans chemin, jamais un .env', async () => {
    calls.length = 0
    const snapshot = await load().snapshot()
    const diff = await snapshot!.diff()

    assert.match(diff, /\+const KEY = 1/)
    assert.ok(calls.length > 0)
    assert.ok(calls.every((target) => typeof target === 'string'), 'aucun appel sans chemin')
    assert.ok(!calls.some((target) => String(target).endsWith('.env')), '.env jamais demandé')
  })

  it('une ligne ajoutée à un fichier suivi est attribuée au changement', async () => {
    const analysis = await new GitSecurityService({
      workspace: load(),
      knownFindings: () => [
        finding({ id: 'nouveau', category: 'SECRET', severity: 'CRITICAL', file: 'web/app.js', line_start: 3, line_end: 3 }),
        finding({ id: 'ancien', severity: 'HIGH', file: 'web/app.js', line_start: 1, line_end: 1 }),
      ],
      ignore: () => ({ ignores: () => false }),
      maxChangedFiles: () => 50,
      log: () => undefined,
    }).analyze()

    assert.deepEqual(analysis.introduced.map((item) => item.finding.id), ['nouveau'])
    assert.ok(analysis.preExisting.some((item) => item.finding.id === 'ancien'))
  })
})
