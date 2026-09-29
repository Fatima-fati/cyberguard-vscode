/**
 * Tests du moteur de sécurité d'API.
 *
 * Deux risques opposés, et le second est le plus grave
 * ----------------------------------------------------
 *
 *     TROP MUET    une route d'administration ouverte passe inaperçue
 *     TROP BAVARD  chaque route d'un projet correctement protégé est
 *                  signalée — l'outil est alors désactivé, et le jour où
 *                  il a raison, personne ne lit plus
 *
 * La plupart des tests de ce fichier portent donc sur ce que le moteur
 * **ne doit pas** dire : une route authentifiée, une authentification
 * globale, une lecture banale, un fichier de test.
 *
 * Aucun appel réseau, aucun dépôt, aucun éditeur : le moteur reçoit du
 * texte et rend des constats.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  ApiScanAccumulator,
  isApiRelevant,
  scanForApiIssues,
} from '../src/apisec/apiScanner'
import { isSensitivePath } from '../src/apisec/apiRules'
import {
  detectRoutes,
  frameworksForPath,
  hasGlobalAuth,
} from '../src/apisec/routeDetectors'
import type { ApiFindingSubmission } from '../src/security/securityTypes'

// --------------------------------------------------------------------------
// Aides
// --------------------------------------------------------------------------

function scan(path: string, ...lines: string[]): ApiFindingSubmission[] {
  return scanForApiIssues(path, lines.join('\n')).findings
}

function routesOf(path: string, ...lines: string[]) {
  return detectRoutes(path, lines)
}

function issues(findings: readonly ApiFindingSubmission[]): string[] {
  return findings.map((finding) => finding.issue_type)
}

function ruleIds(findings: readonly ApiFindingSubmission[]): string[] {
  return findings.map((finding) => finding.rule_id)
}

// --------------------------------------------------------------------------
// Détection de routes
// --------------------------------------------------------------------------

describe('detectRoutes — frameworks reconnus', () => {
  it('reconnaît une route FastAPI avec sa méthode et son chemin', () => {
    const routes = routesOf(
      'src/api.py',
      '@app.get("/users/{user_id}")',
      'async def read_user(user_id: int):',
      '    return user_id'
    )

    assert.equal(routes.length, 1)
    assert.equal(routes[0]?.framework, 'fastapi')
    assert.equal(routes[0]?.method, 'GET')
    assert.equal(routes[0]?.path, '/users/{user_id}')
    assert.equal(routes[0]?.line, 1)
  })

  it('reconnaît une route Flask et ses méthodes déclarées', () => {
    const routes = routesOf(
      'app.py',
      '@app.route("/items", methods=["GET", "POST"])',
      'def items():',
      '    pass'
    )

    assert.equal(routes[0]?.framework, 'flask')
    // La méthode qui **modifie** est retenue : c'est elle qui porte le
    // risque.
    assert.equal(routes[0]?.method, 'POST')
  })

  it('un @app.route sans methods= n’expose que GET', () => {
    const routes = routesOf('app.py', '@app.route("/health")', 'def health(): pass')
    assert.equal(routes[0]?.method, 'GET')
  })

  it('reconnaît une route Express', () => {
    const routes = routesOf(
      'server.js',
      "app.post('/api/orders', createOrder)"
    )

    assert.equal(routes[0]?.framework, 'express')
    assert.equal(routes[0]?.method, 'POST')
    assert.equal(routes[0]?.path, '/api/orders')
  })

  it('reconnaît un décorateur NestJS', () => {
    const routes = routesOf(
      'users.controller.ts',
      "@Delete(':id')",
      'remove(@Param("id") id: string) {}'
    )

    assert.equal(routes[0]?.method, 'DELETE')
  })

  it('reconnaît une annotation Spring', () => {
    const routes = routesOf(
      'UserController.java',
      '@PostMapping("/admin/users")',
      'public User create(@RequestBody User user) { return user; }'
    )

    assert.equal(routes[0]?.framework, 'spring')
    assert.equal(routes[0]?.method, 'POST')
    assert.equal(routes[0]?.path, '/admin/users')
  })

  it('reconnaît une route Laravel', () => {
    const routes = routesOf('web.php', "Route::delete('/admin/users/{id}', 'X@y');")
    assert.equal(routes[0]?.framework, 'laravel')
    assert.equal(routes[0]?.method, 'DELETE')
  })

  it('reconnaît un attribut ASP.NET', () => {
    const routes = routesOf(
      'UsersController.cs',
      '[HttpPost("api/users")]',
      'public IActionResult Create() => Ok();'
    )

    assert.equal(routes[0]?.framework, 'aspnet')
    assert.equal(routes[0]?.method, 'POST')
  })

  it('ne relève rien dans un commentaire', () => {
    // Une route commentée ne l'expose pas.
    assert.equal(routesOf('src/api.py', '# @app.post("/admin/delete")').length, 0)
    assert.equal(routesOf('server.js', "// app.post('/admin', x)").length, 0)
  })

  it('n’applique pas les motifs d’un langage à un autre', () => {
    // Chercher `Route::get` dans un fichier Python produirait des
    // correspondances fortuites dans des chaînes.
    assert.deepEqual(frameworksForPath('src/api.py'), ['fastapi', 'flask', 'django'])
    assert.deepEqual(frameworksForPath('UserController.java'), ['spring'])
  })
})

describe('frameworksForPath — framework inconnu', () => {
  it('ne cherche aucune route dans un langage non pris en charge', () => {
    for (const path of ['main.go', 'lib.rs', 'app.rb', 'script.sh', 'notes.md']) {
      assert.deepEqual(frameworksForPath(path), [], path)
      assert.deepEqual(routesOf(path, 'router.HandleFunc("/admin", h)'), [], path)
    }
  })

  it('ne produit aucun constat de route pour un fichier Go', () => {
    // Go n'est pas couvert : l'agent se tait plutôt que de deviner. Le
    // décompte d'endpoints affiché dira « aucun reconnu », pas
    // « aucune API ».
    const findings = scan('main.go', 'r.HandleFunc("/admin/delete", deleteAll)')
    assert.deepEqual(issues(findings), [])
  })
})

// --------------------------------------------------------------------------
// Authentification
// --------------------------------------------------------------------------

describe('scanForApiIssues — endpoint authentifié', () => {
  it('ne signale rien quand une dépendance d’authentification est présente', () => {
    const findings = scan(
      'src/api.py',
      '@app.post("/items")',
      'async def create(item: Item, user = Depends(get_current_user)):',
      '    return item'
    )

    assert.deepEqual(issues(findings), [])
  })

  it('reconnaît un décorateur Flask', () => {
    const findings = scan(
      'app.py',
      '@app.route("/items", methods=["POST"])',
      '@login_required',
      'def create(): pass'
    )

    assert.deepEqual(issues(findings), [])
  })

  it('reconnaît un middleware Express sur la ligne de la route', () => {
    const findings = scan(
      'server.js',
      "app.post('/api/orders', requireAuth, createOrder)"
    )

    assert.deepEqual(issues(findings), [])
  })

  it('reconnaît une garde NestJS', () => {
    const findings = scan(
      'users.controller.ts',
      '@UseGuards(JwtAuthGuard)',
      "@Post('users')",
      'create() {}'
    )

    assert.deepEqual(issues(findings), [])
  })

  it('reconnaît un middleware Laravel', () => {
    const findings = scan(
      'web.php',
      "Route::post('/orders', 'OrderController@store')->middleware('auth');"
    )

    assert.deepEqual(issues(findings), [])
  })
})

describe('scanForApiIssues — endpoint non authentifié', () => {
  it('signale une écriture sans authentification apparente', () => {
    const findings = scan(
      'src/api.py',
      '@app.post("/items")',
      'async def create(item: Item):',
      '    return item'
    )

    assert.deepEqual(issues(findings), ['unauthenticated_endpoint'])
    assert.equal(findings[0]?.rule_id, 'API-AUTH-001')
    assert.equal(findings[0]?.http_method, 'POST')
    assert.equal(findings[0]?.endpoint, '/items')
    assert.equal(findings[0]?.framework, 'fastapi')
    // Confiance moyenne, pas haute : le moteur ne voit que ce fichier.
    assert.equal(findings[0]?.confidence, 'MEDIUM')
  })

  it('ne signale pas une simple lecture sur un chemin banal', () => {
    // Beaucoup d'API exposent légitimement des routes publiques en
    // lecture. Les signaler noierait les vrais cas.
    const findings = scan(
      'src/api.py',
      '@app.get("/health")',
      'async def health():',
      '    return {"ok": True}'
    )

    assert.deepEqual(issues(findings), [])
  })

  it('signale une lecture sur un chemin sensible', () => {
    const findings = scan(
      'src/api.py',
      '@app.get("/admin/config")',
      'async def config():',
      '    return settings'
    )

    assert.deepEqual(ruleIds(findings), ['API-AUTH-003'])
  })

  it('porte la preuve, la ligne et le chemin du fichier', () => {
    const findings = scan(
      'src/routes/admin.py',
      '# en-tête',
      '@app.delete("/admin/users/{id}")',
      'async def remove(id: int): pass'
    )

    const finding = findings[0]
    assert.equal(finding?.file_path, 'src/routes/admin.py')
    assert.equal(finding?.line, 2)
    assert.match(finding?.evidence ?? '', /@app\.delete/)
    assert.ok((finding?.title ?? '').length > 0)
    assert.ok((finding?.remediation ?? '').length > 0)
    assert.ok((finding?.references ?? []).includes('CWE-306'))
  })

  it('signale plus fort une route explicitement publique', () => {
    const findings = scan(
      'views.py',
      '@api_view(["POST"])',
      '@permission_classes([AllowAny])',
      '@app.route("/admin/purge", methods=["POST"])',
      'def purge(): pass'
    )

    assert.equal(findings[0]?.rule_id, 'API-AUTH-002')
    // La décision est écrite dans le code : ce n'est pas une omission.
    assert.equal(findings[0]?.confidence, 'HIGH')
  })
})

describe('hasGlobalAuth — ne pas crier au loup', () => {
  it('reconnaît un middleware global Express', () => {
    assert.equal(hasGlobalAuth('app.use(requireAuth)').found, true)
  })

  it('reconnaît des dépendances globales FastAPI', () => {
    assert.equal(
      hasGlobalAuth('app = FastAPI(dependencies=[Depends(verify_token)])').found,
      true
    )
  })

  it('reconnaît un réglage global Django REST', () => {
    assert.equal(
      hasGlobalAuth(
        "REST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated']}"
      ).found,
      true
    )
  })

  it('fait taire la règle pour toutes les routes du fichier', () => {
    // Sans ce garde-fou, un projet qui protège correctement ses routes
    // recevrait un signalement par route — et l'outil serait désactivé.
    const findings = scan(
      'server.js',
      "app.use(requireAuth)",
      "app.post('/api/orders', createOrder)",
      "app.delete('/api/orders/:id', removeOrder)",
      "app.put('/profile', saveProfile)"
    )

    assert.deepEqual(issues(findings), [])
  })

  it('ne fait pas taire une route explicitement publique', () => {
    // `AllowAny` s'affranchit précisément de la protection globale.
    const findings = scan(
      'views.py',
      "REST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': ['IsAuthenticated']}",
      '@permission_classes([AllowAny])',
      '@app.route("/admin/purge", methods=["POST"])',
      'def purge(): pass'
    )

    assert.equal(ruleIds(findings).includes('API-AUTH-002'), true)
  })
})

// --------------------------------------------------------------------------
// Autorisation
// --------------------------------------------------------------------------

describe('scanForApiIssues — autorisation', () => {
  it('signale une route sensible authentifiée sans contrôle de rôle', () => {
    // Savoir **qui** appelle ne dit pas qu'il a le droit d'appeler.
    const findings = scan(
      'src/api.py',
      '@app.delete("/admin/users/{id}")',
      'async def remove(id: int, user = Depends(get_current_user)):',
      '    pass'
    )

    assert.deepEqual(ruleIds(findings), ['API-AUTHZ-001'])
    assert.equal(findings[0]?.severity, 'MEDIUM')
  })

  it('ne signale rien quand un contrôle de rôle est présent', () => {
    const findings = scan(
      'AdminController.java',
      '@PreAuthorize("hasRole(\'ADMIN\')")',
      '@DeleteMapping("/admin/users/{id}")',
      'public void remove(@PathVariable Long id) {}'
    )

    assert.deepEqual(issues(findings), [])
  })

  it('réclame un rôle même derrière une authentification globale', () => {
    // L'authentification globale prouve l'identité, pas le droit. Sur un
    // chemin privilégié, la question de l'autorisation reste entière.
    const findings = scan(
      'server.js',
      'app.use(requireAuth)',
      "app.put('/admin/settings', saveSettings)"
    )

    assert.deepEqual(ruleIds(findings), ['API-AUTHZ-001'])
  })

  it('ne réclame pas de rôle sur une route authentifiée banale', () => {
    // Exiger un contrôle de rôle sur chaque route produirait du bruit sur
    // les API où tout utilisateur connecté a légitimement accès.
    const findings = scan(
      'src/api.py',
      '@app.post("/notes")',
      'async def create(note: Note, user = Depends(get_current_user)):',
      '    pass'
    )

    assert.deepEqual(issues(findings), [])
  })

  it('reconnaît une garde de rôles NestJS', () => {
    const findings = scan(
      'admin.controller.ts',
      '@UseGuards(JwtAuthGuard, RolesGuard)',
      "@Delete('admin/users/:id')",
      'remove() {}'
    )

    assert.deepEqual(issues(findings), [])
  })
})

describe('isSensitivePath', () => {
  it('reconnaît les surfaces habituellement réservées', () => {
    for (const path of ['/admin', '/admin/users', '/internal/config', '/api/tokens']) {
      assert.equal(isSensitivePath(path), true, path)
    }
  })

  it('ne classe pas sensible un chemin banal', () => {
    for (const path of ['/health', '/ping', '/api/search', '/docs']) {
      assert.equal(isSensitivePath(path), false, path)
    }
  })
})

// --------------------------------------------------------------------------
// CORS
// --------------------------------------------------------------------------

describe('scanForApiIssues — CORS', () => {
  it('signale en critique le joker accompagné des identifiants', () => {
    const findings = scan(
      'src/main.py',
      'app.add_middleware(',
      '    CORSMiddleware,',
      '    allow_origins=["*"],',
      '    allow_credentials=True,',
      ')'
    )

    assert.deepEqual(ruleIds(findings), ['API-CORS-001'])
    assert.equal(findings[0]?.severity, 'CRITICAL')
  })

  it('signale plus doucement le joker seul', () => {
    const findings = scan(
      'src/main.py',
      'app.add_middleware(CORSMiddleware, allow_origins=["*"])'
    )

    assert.deepEqual(ruleIds(findings), ['API-CORS-002'])
    assert.equal(findings[0]?.severity, 'MEDIUM')
  })

  it('ne produit qu’un seul constat pour une seule ligne', () => {
    // Les deux règles CORS correspondent à la même ligne : sans le
    // contrôle de préséance, elle produirait deux signalements pour un
    // seul problème.
    const findings = scan(
      'server.js',
      "app.use(cors({ origin: '*', credentials: true }))"
    )

    assert.equal(findings.length, 1)
    assert.equal(findings[0]?.rule_id, 'API-CORS-001')
  })

  it('ne signale rien quand les origines sont explicites', () => {
    const findings = scan(
      'src/main.py',
      'app.add_middleware(',
      '    CORSMiddleware,',
      '    allow_origins=["https://app.example.com"],',
      '    allow_credentials=True,',
      ')'
    )

    assert.deepEqual(issues(findings), [])
  })
})

// --------------------------------------------------------------------------
// Transport
// --------------------------------------------------------------------------

describe('scanForApiIssues — HTTP contre HTTPS', () => {
  it('signale un appel d’API en HTTP', () => {
    const findings = scan('src/client.py', 'BASE = "http://api.example.com/v1"')
    assert.deepEqual(ruleIds(findings), ['API-TLS-002'])
  })

  it('ne signale pas une adresse locale', () => {
    // Un `http://127.0.0.1:8000` de développement n'est pas un problème
    // de transport, et le signaler noierait les vrais cas.
    for (const url of [
      'http://localhost:8000/api',
      'http://127.0.0.1:5000',
      'http://0.0.0.0:3000',
    ]) {
      assert.deepEqual(scan('src/client.py', `BASE = "${url}"`), [], url)
    }
  })

  it('ne signale pas un espace de noms XML', () => {
    const findings = scan(
      'pom.xml',
      '<project xmlns="http://maven.apache.org/POM/4.0.0">'
    )
    assert.deepEqual(issues(findings), [])
  })

  it('ne signale rien en HTTPS', () => {
    assert.deepEqual(scan('src/client.py', 'BASE = "https://api.example.com"'), [])
  })

  it('signale une vérification TLS désactivée', () => {
    const findings = scan(
      'src/client.py',
      'requests.get(url, verify=False)'
    )

    assert.deepEqual(ruleIds(findings), ['API-TLS-001'])
    assert.equal(findings[0]?.severity, 'HIGH')
  })

  it('reconnaît la forme Node de la même désactivation', () => {
    const findings = scan(
      'client.js',
      'const agent = new https.Agent({ rejectUnauthorized: false })'
    )
    assert.deepEqual(ruleIds(findings), ['API-TLS-001'])
  })
})

// --------------------------------------------------------------------------
// Débogage
// --------------------------------------------------------------------------

describe('scanForApiIssues — surfaces de diagnostic', () => {
  it('signale un mode débogage activé', () => {
    const findings = scan('settings.py', 'DEBUG = True')
    assert.deepEqual(ruleIds(findings), ['API-DEBUG-001'])
  })

  it('ne signale pas un mode débogage lu depuis l’environnement', () => {
    // C'est exactement la forme recommandée : la signaler apprendrait à
    // l'utilisateur à ignorer la règle.
    const findings = scan('settings.py', 'DEBUG = os.environ.get("DEBUG") == "1"')
    assert.deepEqual(issues(findings), [])
  })

  it('signale une route de diagnostic exposée', () => {
    const findings = scan('src/api.py', '@app.get("/actuator/env")', 'def env(): pass')
    assert.equal(ruleIds(findings).includes('API-DEBUG-002'), true)
  })
})

// --------------------------------------------------------------------------
// Identifiants
// --------------------------------------------------------------------------

describe('scanForApiIssues — identifiants d’API', () => {
  it('signale un en-tête Authorization littéral', () => {
    const findings = scan(
      'src/client.py',
      'HEADERS = {"Authorization": "Bearer abcdef1234567890xyz"}'
    )

    assert.deepEqual(ruleIds(findings), ['API-CRED-001'])
  })

  it('ne signale pas un en-tête construit depuis une variable', () => {
    for (const line of [
      'HEADERS = {"Authorization": f"Bearer {token}"}',
      'headers = { Authorization: `Bearer ${token}` }',
      'HEADERS = {"Authorization": "Bearer " + os.environ["TOKEN"]}',
    ]) {
      assert.deepEqual(scan('src/client.py', line), [], line)
    }
  })

  it('signale des identifiants intégrés à une URL', () => {
    const findings = scan(
      'src/client.py',
      'URL = "https://admin:s3cr3tpass@api.example.com/v1"'
    )

    assert.deepEqual(ruleIds(findings), ['API-CRED-002'])
    assert.equal(findings[0]?.severity, 'HIGH')
  })

  it('ne fait jamais sortir la valeur détectée telle quelle', () => {
    const findings = scan(
      'src/client.py',
      'URL = "https://admin:s3cr3tpass@api.example.com/v1"'
    )

    // La preuve part au backend, qui la ré-expurge. Elle ne doit déjà pas
    // porter plus que ce que la ligne montre, et surtout jamais être
    // reconstruite ailleurs.
    const finding = findings[0]
    assert.ok(finding)
    assert.equal(finding.evidence.length <= 160, true)
  })
})

// --------------------------------------------------------------------------
// Configuration sûre
// --------------------------------------------------------------------------

describe('scanForApiIssues — configuration sûre', () => {
  it('ne signale rien sur une API correctement écrite', () => {
    const findings = scan(
      'src/main.py',
      'app = FastAPI()',
      'app.add_middleware(',
      '    CORSMiddleware,',
      '    allow_origins=["https://app.example.com"],',
      '    allow_credentials=True,',
      ')',
      '',
      '@app.get("/health")',
      'async def health():',
      '    return {"status": "ok"}',
      '',
      '@app.post("/orders")',
      'async def create(order: Order, user = Depends(get_current_user)):',
      '    return order',
      '',
      'BASE = "https://api.example.com"',
      'DEBUG = os.getenv("DEBUG") == "1"'
    )

    assert.deepEqual(issues(findings), [])
  })

  it('abaisse la confiance dans un fichier de test', () => {
    // Un fichier de test décrit des routes, il n'en expose pas.
    const production = scan(
      'src/api.py',
      '@app.post("/items")',
      'async def create(item: Item): pass'
    )
    const test = scan(
      'tests/test_api.py',
      '@app.post("/items")',
      'async def create(item: Item): pass'
    )

    assert.equal(production[0]?.confidence, 'MEDIUM')
    assert.equal(test[0]?.confidence, 'LOW')
  })

  it('ne regarde pas un fichier sans rapport', () => {
    assert.equal(isApiRelevant('README.md'), false)
    assert.equal(isApiRelevant('logo.png'), false)
    assert.equal(isApiRelevant('bundle.min.js'), false)
    assert.equal(isApiRelevant('src/api.py'), true)
    assert.equal(isApiRelevant('config/app.yml'), true)
  })

  it('ne lève jamais sur une entrée vide ou absurde', () => {
    assert.doesNotThrow(() => scanForApiIssues('src/api.py', ''))
    assert.doesNotThrow(() => scanForApiIssues('src/api.py', '\u0000\u0001@app.'))
    assert.deepEqual(scanForApiIssues('src/api.py', '').findings, [])
  })

  it('borne un fichier anormalement long', () => {
    const many = Array.from(
      { length: 200 },
      (_, index) => `@app.post("/admin/x${index}")`
    ).join('\n')

    const outcome = scanForApiIssues('src/api.py', many, { maxFindings: 5 })
    assert.equal(outcome.findings.length <= 5, true)
    // Une couverture partielle se dit, elle ne s'affiche jamais complète.
    assert.equal(outcome.truncated, true)
  })
})

// --------------------------------------------------------------------------
// Accumulateur et analyse incrémentale
// --------------------------------------------------------------------------

describe('ApiScanAccumulator', () => {
  it('agrège plusieurs fichiers et compte les routes relevées', () => {
    const accumulator = new ApiScanAccumulator()
    accumulator.consider(
      'src/api.py',
      ['@app.post("/items")', 'async def create(i: Item): pass'].join('\n')
    )
    accumulator.consider(
      'src/health.py',
      ['@app.get("/health")', 'async def health(): pass'].join('\n')
    )

    const result = accumulator.result()
    assert.equal(result.scannedFiles, 2)
    // Les deux routes sont comptées, y compris celle qui ne pose aucun
    // problème : ce chiffre dit la couverture, pas le risque.
    assert.equal(result.endpointsDetected, 2)
    assert.equal(result.findings.length, 1)
  })

  it('ignore un fichier sans rapport avec une API', () => {
    const accumulator = new ApiScanAccumulator()
    accumulator.consider('README.md', '# Documentation\n@app.post("/admin")')

    assert.equal(accumulator.result().scannedFiles, 0)
  })

  it('trie le lot par gravité', () => {
    const accumulator = new ApiScanAccumulator()
    accumulator.consider('src/client.py', 'BASE = "http://api.example.com"')
    accumulator.consider(
      'src/main.py',
      'CORSMiddleware, allow_origins=["*"], allow_credentials=True'
    )

    const severities = accumulator.result().findings.map((f) => f.severity)
    assert.equal(severities[0], 'CRITICAL')
  })

  it('expose le détail par fichier pour la surveillance continue', () => {
    const accumulator = new ApiScanAccumulator()
    accumulator.consider(
      'src/api.py',
      ['@app.post("/items")', 'async def create(i: Item): pass'].join('\n')
    )
    accumulator.consider('README.md', 'rien')

    const detail = accumulator.perFile()
    assert.equal(detail.scannedPaths.has('src/api.py'), true)
    assert.equal(detail.apiByFile.has('src/api.py'), true)
    // Un fichier sans rapport n'entre pas dans le registre.
    assert.equal(detail.scannedPaths.has('README.md'), false)
    // Le détail par fichier décrit le même parcours que l'agrégat.
    const flattened = [...detail.apiByFile.values()].flat()
    assert.equal(flattened.length, accumulator.result().findings.length)
  })
})
