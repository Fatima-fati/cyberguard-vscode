/**
 * Tests du moteur de détection de secrets.
 *
 * Trois familles de garanties, dans l'ordre de leur importance :
 *
 *     SÉCURITÉ        aucune valeur détectée ne survit à la détection —
 *                     c'est la garantie qui, si elle tombait, rendrait la
 *                     fonctionnalité pire que son absence
 *     DÉTECTION       les formes de clés annoncées sont bien reconnues,
 *                     dans tous les langages annoncés
 *     FAUX POSITIFS   un placeholder n'est jamais signalé, un contexte de
 *                     test abaisse la confiance sans faire taire
 *
 * Les valeurs utilisées ici sont **fabriquées**. Aucune n'est une clé
 * réelle : elles respectent la forme (préfixe, longueur, alphabet) et rien
 * d'autre.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  cappedSeverity,
  downgrade,
  isLowTrustPath,
  isPlaceholder,
  shannonEntropy,
} from '../src/security/falsePositives'
import { MASK, buildEvidence, isRedacted, redactSecret } from '../src/security/redaction'
import { SECRET_PATTERNS } from '../src/security/secretPatterns'
import {
  SecretScanAccumulator,
  scanForSecrets,
} from '../src/security/secretScanner'
import type { SecretFindingSubmission } from '../src/security/securityTypes'

// --------------------------------------------------------------------------
// Échantillons fabriqués
// --------------------------------------------------------------------------

const SAMPLE = {
  openai: 'sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6',
  anthropic: 'sk-ant-api03-A1b2C3d4E5f6G7h8I9j0K1l2M3n4',
  awsKeyId: 'AKIAIOSFODNN7EXAMPLE',
  awsSecret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1',
  github: 'ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8',
  gitlab: 'glpat-A1b2C3d4E5f6G7h8I9j0',
  slack: 'xoxb-123456789012-345678901234-A1b2C3d4E5f6G7h8I9j0K1l2',
  google: 'AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q',
  stripe: 'sk_live_A1b2C3d4E5f6G7h8I9j0K1l2',
  npm: 'npm_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8',
  jwt:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' +
    'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.' +
    'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
  jwtSecret: 'zK7pQ2mR9xL4vB8nT3wY6cF1hJ5dG0sA',
  dbPassword: 'pR7x2Kq9Lm4Zt8Vb',
} as const

/** Raccourci : premier finding d'un texte, ou `undefined`. */
function firstFinding(
  path: string,
  text: string
): SecretFindingSubmission | undefined {
  return scanForSecrets(path, text).findings[0]
}

/** Tous les types de secrets détectés dans un texte. */
function typesIn(path: string, text: string): string[] {
  return scanForSecrets(path, text).findings.map((finding) => finding.secret_type)
}

// --------------------------------------------------------------------------
// Sécurité : la garantie qui prime sur toutes les autres
// --------------------------------------------------------------------------

describe('détection de secrets — la valeur n’est jamais conservée', () => {
  it('aucun finding ne porte la valeur détectée, quel que soit le motif', () => {
    // Un fichier qui contient toutes les formes reconnues d'un coup : si
    // un seul motif laissait passer sa valeur, ce test le voit.
    const source = Object.values(SAMPLE)
      .map((value, index) => `const secret${index} = "${value}"`)
      .join('\n')

    const { findings } = scanForSecrets('src/leak.ts', source, { maxFindings: 100 })
    assert.ok(findings.length > 0, 'aucun secret détecté : le test serait vide')

    for (const finding of findings) {
      const serialized = JSON.stringify(finding)
      for (const value of Object.values(SAMPLE)) {
        assert.ok(
          !serialized.includes(value),
          `la valeur complète apparaît dans le finding ${finding.rule_id}`
        )
      }
    }
  })

  it('chaque preuve porte un masque et passe le contrôle d’expurgation', () => {
    const { findings } = scanForSecrets(
      'backend/config.py',
      `OPENAI_API_KEY = "${SAMPLE.openai}"`
    )

    const finding = findings[0]
    assert.ok(finding)
    assert.ok(finding.evidence_redacted.includes(MASK))
    assert.ok(isRedacted(finding.evidence_redacted))
  })

  it('la preuve montre assez pour reconnaître, trop peu pour rejouer', () => {
    const evidence = buildEvidence('OpenAI API key detected', SAMPLE.openai, 8)

    assert.equal(evidence, 'OpenAI API key detected: sk-proj-********')
    // Le nombre de caractères visibles est borné, quoi que demande
    // l'appelant : un `keep` généreux ne peut pas affaiblir l'expurgation.
    assert.equal(redactSecret(SAMPLE.openai, 999), `sk-proj-${MASK}`)
  })

  it('une valeur courte est masquée en entier', () => {
    // Révéler quatre caractères d'un secret de huit réduirait
    // sérieusement l'espace de recherche.
    assert.equal(redactSecret('abc123', 4), MASK)
    assert.equal(redactSecret('short', 4), MASK)
  })

  it('le corps d’une clé privée n’est jamais capturé', () => {
    const block = [
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEowIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz',
      '-----END RSA PRIVATE KEY-----',
    ].join('\n')

    const finding = firstFinding('deploy/key.txt', block)
    assert.ok(finding)
    assert.equal(finding.secret_type, 'private_key')
    // Seul l'en-tête est reconnu : le corps n'entre jamais dans un objet
    // qui survit à la ligne lue.
    assert.ok(!finding.evidence_redacted.includes('MIIEowIBAAKCAQEA'))
  })

  it('le contrôle d’expurgation refuse une valeur laissée en clair', () => {
    assert.equal(isRedacted(`token: ${SAMPLE.github}`), false)
    assert.equal(isRedacted(`token: ghp_A1b2${MASK}`), true)
    // Un mot français ou un nom de variable n'est pas une fuite : le
    // masquer rendrait la preuve illisible sans rien protéger.
    assert.equal(isRedacted('Identifiants de base de données détectés'), true)
  })
})

// --------------------------------------------------------------------------
// Détection par type
// --------------------------------------------------------------------------

describe('détection de secrets — formes reconnues', () => {
  const cases: readonly [string, string, string][] = [
    ['clé OpenAI', `api_key = "${SAMPLE.openai}"`, 'openai_api_key'],
    ['clé Anthropic', `key = "${SAMPLE.anthropic}"`, 'anthropic_api_key'],
    ['identifiant AWS', `aws_id = "${SAMPLE.awsKeyId}"`, 'aws_access_key_id'],
    [
      'clé secrète AWS',
      `aws_secret_access_key = "${SAMPLE.awsSecret}"`,
      'aws_secret_access_key',
    ],
    ['jeton GitHub', `token: ${SAMPLE.github}`, 'github_token'],
    ['jeton GitLab', `CI_TOKEN=${SAMPLE.gitlab}`, 'gitlab_token'],
    ['jeton Slack', `slack = '${SAMPLE.slack}'`, 'slack_token'],
    ['clé Google', `googleKey: "${SAMPLE.google}"`, 'google_api_key'],
    ['clé Stripe', `STRIPE = "${SAMPLE.stripe}"`, 'stripe_secret_key'],
    ['jeton npm', `//registry.npmjs.org/:_authToken=${SAMPLE.npm}`, 'npm_token'],
    ['JWT', `const t = "${SAMPLE.jwt}"`, 'jwt_token'],
    [
      'secret de signature JWT',
      `JWT_SECRET = "${SAMPLE.jwtSecret}"`,
      'jwt_secret',
    ],
    [
      'identifiants de base de données',
      `DATABASE_URL = "postgresql://app:${SAMPLE.dbPassword}@db.internal:5432/prod"`,
      'database_credentials',
    ],
    [
      'mot de passe en dur',
      `db_password = "${SAMPLE.dbPassword}"`,
      'password',
    ],
    [
      'en-tête Bearer',
      `headers = {"Authorization": "Bearer ${SAMPLE.jwtSecret}0000"}`,
      'bearer_token',
    ],
    [
      'webhook Slack',
      'url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"',
      'slack_webhook',
    ],
    [
      'clé de stockage Azure',
      'conn = "DefaultEndpointsProtocol=https;AccountKey=A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A7b8C9d0=="',
      'azure_storage_key',
    ],
    [
      'compte de service Google Cloud',
      '{"type": "service_account", "project_id": "demo"}',
      'gcp_service_account',
    ],
  ]

  for (const [label, line, expected] of cases) {
    it(`reconnaît : ${label}`, () => {
      const types = typesIn('src/app.ts', line)
      assert.ok(
        types.includes(expected),
        `attendu « ${expected} », obtenu [${types.join(', ')}]`
      )
    })
  }

  it('reconnaît un secret dans chaque syntaxe de langage annoncée', () => {
    // Un seul jeu de motifs couvre toutes ces syntaxes : c'est
    // précisément ce que ce test vérifie, plutôt qu'une table par langage
    // qui aurait divergé au premier ajout.
    const syntaxes: readonly [string, string][] = [
      ['Python', `api_key = "${SAMPLE.openai}"`],
      ['JavaScript', `const apiKey = '${SAMPLE.openai}'`],
      ['TypeScript', `const apiKey: string = \`${SAMPLE.openai}\``],
      ['JSON', `{"api_key": "${SAMPLE.openai}"}`],
      ['YAML', `api_key: ${SAMPLE.openai}`],
      ['TOML', `api_key = "${SAMPLE.openai}"`],
      ['Java', `String apiKey = "${SAMPLE.openai}";`],
      ['PHP', `$apiKey = "${SAMPLE.openai}";`],
      ['Go', `apiKey := "${SAMPLE.openai}"`],
      ['C#', `var apiKey = "${SAMPLE.openai}";`],
      ['Ruby', `API_KEY = '${SAMPLE.openai}'`],
      ['.properties', `api.key=${SAMPLE.openai}`],
    ]

    for (const [language, line] of syntaxes) {
      const types = typesIn('src/sample', line)
      assert.ok(
        types.includes('openai_api_key'),
        `${language} : secret non détecté dans « ${line.slice(0, 30)}… »`
      )
    }
  })

  it('reporte la ligne et la colonne exactes', () => {
    const source = ['# en-tête', '', `OPENAI_API_KEY = "${SAMPLE.openai}"`].join('\n')

    const finding = firstFinding('backend/config.py', source)
    assert.ok(finding)
    assert.equal(finding.line, 3)
    assert.equal(typeof finding.column, 'number')
  })

  it('ne signale qu’une fois le même secret sur une ligne', () => {
    // Une clé OpenAI est aussi, littéralement, « une valeur affectée à
    // une variable nommée api_key ». Sans l'ordre des motifs et la
    // déduplication, elle serait signalée deux fois.
    const { findings } = scanForSecrets(
      'src/app.ts',
      `const api_key = "${SAMPLE.openai}"`
    )
    const openai = findings.filter((item) => item.secret_type === 'openai_api_key')
    assert.equal(openai.length, 1)
  })
})

// --------------------------------------------------------------------------
// Faux positifs
// --------------------------------------------------------------------------

describe('détection de secrets — faux positifs écartés', () => {
  const placeholders: readonly string[] = [
    'api_key = "${API_KEY}"',
    'api_key = "$API_KEY"',
    'api_key = "{{ api_key }}"',
    'api_key = "%API_KEY%"',
    'api_key = "<API_KEY>"',
    'api_key = "YOUR_API_KEY"',
    'api_key = "your-api-key-here"',
    'api_key = "CHANGE_ME"',
    'api_key = "changeme123"',
    'api_key = "xxxxxxxxxxxx"',
    'api_key = "placeholder"',
    'api_key = "example_value"',
    'api_key = process.env.API_KEY',
    'api_key = os.environ["API_KEY"]',
    'api_key = System.getenv("API_KEY")',
    'password = "REPLACE_ME"',
    'DATABASE_URL = "postgresql://user:password@example.com:5432/db"',
  ]

  for (const line of placeholders) {
    it(`n’en fait pas un secret : ${line.slice(0, 44)}`, () => {
      assert.deepEqual(typesIn('backend/config.py', line), [])
    })
  }

  it('reconnaît les formes de substitution sans les confondre avec des valeurs', () => {
    assert.equal(isPlaceholder('${API_KEY}'), true)
    assert.equal(isPlaceholder('YOUR_API_KEY'), true)
    assert.equal(isPlaceholder('your-api-key'), true)
    assert.equal(isPlaceholder('CHANGE_ME'), true)
    assert.equal(isPlaceholder('https://example.com/callback'), true)
    assert.equal(isPlaceholder(SAMPLE.openai), false)
    assert.equal(isPlaceholder(SAMPLE.jwtSecret), false)
  })

  it('abaisse la confiance dans un fichier de test, sans faire taire', () => {
    // Le finding est conservé : des clés réelles se retrouvent dans des
    // fixtures, et c'est précisément là qu'on oublie de les faire tourner.
    const production = firstFinding('src/config.ts', `api_key = "${SAMPLE.openai}"`)
    const fixture = firstFinding(
      'tests/fixtures/config.ts',
      `api_key = "${SAMPLE.openai}"`
    )

    assert.ok(production)
    assert.ok(fixture, 'un secret dans un fichier de test doit rester signalé')
    assert.equal(production.confidence, 'HIGH')
    assert.equal(fixture.confidence, 'MEDIUM')
  })

  it('reconnaît les chemins de moindre confiance', () => {
    assert.equal(isLowTrustPath('tests/conftest.py'), true)
    assert.equal(isLowTrustPath('src/__tests__/app.test.ts'), true)
    assert.equal(isLowTrustPath('docs/quickstart.md'), true)
    assert.equal(isLowTrustPath('examples/demo.py'), true)
    assert.equal(isLowTrustPath('.env.example'), true)
    assert.equal(isLowTrustPath('src/config.ts'), false)
  })

  it('l’entropie départage ce qu’un motif large ne peut pas trancher', () => {
    assert.ok(shannonEntropy('abababababab') < shannonEntropy(SAMPLE.jwtSecret))
    // Une valeur de faible entropie reste signalée — un mot de passe
    // faible est un mot de passe — mais avec une confiance moindre.
    const faible = firstFinding('src/app.py', 'db_password = "abababababab"')
    const forte = firstFinding('src/app.py', `db_password = "${SAMPLE.dbPassword}"`)
    assert.ok(faible)
    assert.ok(forte)
    assert.equal(faible.confidence, 'LOW')
    assert.equal(forte.confidence, 'MEDIUM')
  })
})

// --------------------------------------------------------------------------
// Gravité et confiance
// --------------------------------------------------------------------------

describe('détection de secrets — gravité plafonnée par la confiance', () => {
  it('une détection de faible confiance ne s’affiche jamais en CRITICAL', () => {
    // La règle protège la crédibilité du signal : une liste de critiques
    // où un sur deux est faux cesse d'être lue.
    assert.equal(cappedSeverity('CRITICAL', 'LOW'), 'MEDIUM')
    assert.equal(cappedSeverity('HIGH', 'LOW'), 'MEDIUM')
    assert.equal(cappedSeverity('LOW', 'LOW'), 'LOW')
  })

  it('une confiance moyenne abaisse CRITICAL d’un cran', () => {
    assert.equal(cappedSeverity('CRITICAL', 'MEDIUM'), 'HIGH')
    assert.equal(cappedSeverity('HIGH', 'MEDIUM'), 'HIGH')
  })

  it('une confiance haute laisse la gravité intacte', () => {
    assert.equal(cappedSeverity('CRITICAL', 'HIGH'), 'CRITICAL')
    assert.equal(cappedSeverity('MEDIUM', 'HIGH'), 'MEDIUM')
  })

  it('le déclassement s’arrête à LOW', () => {
    assert.equal(downgrade('HIGH'), 'MEDIUM')
    assert.equal(downgrade('MEDIUM'), 'LOW')
    assert.equal(downgrade('LOW'), 'LOW')
    assert.equal(downgrade('HIGH', 5), 'LOW')
  })

  it('un secret critique et sûr reste critique', () => {
    const finding = firstFinding('backend/config.py', `API_KEY = "${SAMPLE.openai}"`)
    assert.ok(finding)
    assert.equal(finding.severity, 'CRITICAL')
    assert.equal(finding.confidence, 'HIGH')
  })
})

// --------------------------------------------------------------------------
// Bornes
// --------------------------------------------------------------------------

describe('détection de secrets — bornes', () => {
  it('ignore une ligne trop longue plutôt que d’y chercher du bruit', () => {
    // Un bundle minifié tient sur une seule ligne : l'analyser coûte cher
    // et ne trouve que des correspondances sans valeur.
    const minified = `${'a'.repeat(3000)} api_key = "${SAMPLE.openai}"`
    assert.deepEqual(typesIn('dist/app.js', minified), [])
  })

  it('n’analyse pas un fichier généré', () => {
    assert.deepEqual(
      typesIn('dist/vendor.min.js', `api_key = "${SAMPLE.openai}"`),
      []
    )
  })

  it('annonce la troncature plutôt que de la taire', () => {
    const lines = Array.from(
      { length: 40 },
      (_, index) => `key${index} = "${SAMPLE.openai}${index}"`
    )
    const outcome = scanForSecrets('src/many.ts', lines.join('\n'), {
      maxFindings: 5,
    })

    assert.equal(outcome.findings.length, 5)
    assert.equal(outcome.truncated, true)
  })

  it('un texte vide ne produit rien et n’échoue pas', () => {
    assert.deepEqual(scanForSecrets('src/empty.ts', '').findings, [])
  })
})

// --------------------------------------------------------------------------
// Accumulateur
// --------------------------------------------------------------------------

describe('détection de secrets — accumulateur de projet', () => {
  it('compte les fichiers analysés et ceux volontairement ignorés', () => {
    const accumulator = new SecretScanAccumulator()
    accumulator.consider('src/a.ts', 'const x = 1')
    accumulator.consider('backend/config.py', `API_KEY = "${SAMPLE.openai}"`)
    accumulator.skip()

    const result = accumulator.result()
    assert.equal(result.scannedFiles, 2)
    assert.equal(result.skippedFiles, 1)
    assert.equal(result.findings.length, 1)
    assert.equal(result.truncated, false)
  })

  it('classe les plus graves en tête', () => {
    const accumulator = new SecretScanAccumulator()
    accumulator.consider('src/a.py', `db_password = "${SAMPLE.dbPassword}"`)
    accumulator.consider('src/b.py', `API_KEY = "${SAMPLE.openai}"`)

    const [first] = accumulator.result().findings
    assert.ok(first)
    // Si le lot doit être tronqué côté backend, c'est le critique qui
    // doit survivre.
    assert.equal(first.severity, 'CRITICAL')
  })

  it('annonce la troncature quand le plafond du projet est atteint', () => {
    const accumulator = new SecretScanAccumulator(2)
    for (let index = 0; index < 10; index += 1) {
      accumulator.consider(`src/f${index}.py`, `API_KEY = "${SAMPLE.openai}${index}"`)
    }

    const result = accumulator.result()
    assert.equal(result.findings.length, 2)
    assert.equal(result.truncated, true)
  })
})

// --------------------------------------------------------------------------
// Catalogue
// --------------------------------------------------------------------------

describe('catalogue de motifs', () => {
  it('chaque motif porte un identifiant unique', () => {
    const identifiers = SECRET_PATTERNS.map((pattern) => pattern.id)
    assert.equal(new Set(identifiers).size, identifiers.length)
  })

  it('aucun motif n’est global : un lastIndex partagé perdrait des détections', () => {
    for (const pattern of SECRET_PATTERNS) {
      assert.equal(
        pattern.pattern.global,
        false,
        `${pattern.id} porte le drapeau global`
      )
    }
  })

  it('aucun motif ne révèle plus de 8 caractères', () => {
    for (const pattern of SECRET_PATTERNS) {
      assert.ok(pattern.keep <= 8, `${pattern.id} demande ${pattern.keep} caractères`)
    }
  })
})
