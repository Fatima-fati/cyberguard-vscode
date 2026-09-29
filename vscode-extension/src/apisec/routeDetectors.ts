/**
 * Repérage des routes d'API, par framework.
 *
 * Ce module répond à une seule question : *où ce fichier expose-t-il une
 * route, avec quelle méthode, et qu'est-ce qui atteste qu'elle est
 * protégée ?* Il ne juge rien — c'est `apiRules.ts` qui décide si une
 * route constitue un problème.
 *
 * Pourquoi une analyse par lignes, et pas un vrai analyseur syntaxique
 * -------------------------------------------------------------------
 *
 * Un AST par langage voudrait dire embarquer un analyseur Python, un
 * analyseur TypeScript, un analyseur Java et un analyseur PHP dans une
 * extension qui n'a aujourd'hui **aucune dépendance**. Le coût est
 * disproportionné par rapport au gain : les déclarations de routes sont,
 * dans tous ces frameworks, des formes locales et très régulières — un
 * décorateur, ou un appel de méthode sur un objet d'application.
 *
 * Ce choix a une conséquence assumée : cette détection **ne voit que ce
 * qui est écrit littéralement**. Une route montée par métaprogrammation,
 * ou dont le chemin vient d'une variable, ne sera pas vue. C'est une
 * limite documentée, et elle va dans le bon sens — ne rien dire plutôt
 * que d'affirmer à tort.
 *
 * La fenêtre d'observation
 * ------------------------
 *
 * L'authentification n'est presque jamais sur la même ligne que la route.
 * En Python elle est dans la signature qui suit ; en Java dans une
 * annotation au-dessus ; en Express dans les arguments intermédiaires. Le
 * détecteur lit donc une **fenêtre** autour de la déclaration :
 *
 *     décorateurs qui précèdent   @login_required au-dessus de @app.get
 *     ligne de la route           app.get('/x', requireAuth, handler)
 *     signature qui suit          user = Depends(get_current_user)
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

/** Frameworks dont les routes sont reconnues littéralement. */
export type ApiFramework =
  | 'fastapi'
  | 'flask'
  | 'django'
  | 'express'
  | 'nestjs'
  | 'spring'
  | 'laravel'
  | 'aspnet'

/** Méthodes qui modifient un état. Les autres se contentent de lire. */
export const STATE_CHANGING: ReadonlySet<string> = new Set([
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
])

/** Une route déclarée dans le fichier, et ce qui l'entoure. */
export interface DetectedRoute {
  readonly framework: ApiFramework
  /** `GET`, `POST`… ou `ANY` quand la déclaration ne la fixe pas. */
  readonly method: string
  /** Chemin littéral déclaré. Vide si la déclaration ne le porte pas. */
  readonly path: string
  /** Ligne de la déclaration, 1-basée. */
  readonly line: number
  /** Extrait **de la déclaration**, jamais du corps du gestionnaire. */
  readonly evidence: string
  /** Une marque d'authentification a-t-elle été trouvée dans la fenêtre ? */
  readonly authenticated: boolean
  readonly authEvidence: string | null
  /** Une vérification de rôle ou de permission ? */
  readonly authorized: boolean
  readonly authzEvidence: string | null
  /**
   * La route se déclare-t-elle **explicitement** publique ?
   *
   * `AllowAny`, `permission_classes = []`, `@AllowAnonymous`. C'est une
   * information de confiance élevée : le développeur l'a écrit.
   */
  readonly explicitlyPublic: boolean
  readonly publicEvidence: string | null
}

// --------------------------------------------------------------------------
// Marques d'authentification et d'autorisation
// --------------------------------------------------------------------------

/**
 * Ce qui atteste qu'une route est protégée.
 *
 * Les noms sont conventionnels et se ressemblent d'un écosystème à
 * l'autre : une seule table sert tous les langages. Elle est
 * volontairement **large** — un faux « c'est protégé » fait taire un
 * signalement, ce qui est moins grave qu'un faux « ce n'est pas
 * protégé », qui use la crédibilité de l'outil.
 */
const AUTH_MARKERS: readonly RegExp[] = [
  // Python — FastAPI / Starlette
  /\bDepends\s*\(\s*[\w.]*(?:current_user|active_user|get_user|auth|token|jwt|verify|require|login|session|principal|identity)/i,
  /\bSecurity\s*\(/,
  /\bHTTPBearer\s*\(|\bOAuth2PasswordBearer\s*\(|\bAPIKeyHeader\s*\(/,
  // Python — Flask / Django
  /@\w*(?:login_required|jwt_required|token_required|requires_auth|authenticated|auth_required)/i,
  /\bpermission_classes\s*=\s*\[\s*(?!\s*\])[^\]]+\]/,
  /\bIsAuthenticated\b|\bIsAdminUser\b|\bTokenAuthentication\b/,
  /@\w*(?:permission_required|user_passes_test|staff_member_required)/i,
  // JavaScript / TypeScript
  /\bpassport\s*\.\s*authenticate\s*\(/,
  /\b(?:requireAuth|ensureAuth|ensureAuthenticated|isAuthenticated|checkAuth|authGuard|authMiddleware|verifyToken|verifyJwt|authenticateToken|requireLogin|withAuth)\b/i,
  /\bexpressJwt\s*\(|\bexpress-jwt\b/,
  // NestJS
  /@UseGuards\s*\(/,
  // Java — Spring
  /@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed)\b/,
  // PHP — Laravel
  /->\s*middleware\s*\(\s*\[?\s*['"](?:auth|auth:[\w-]+|sanctum|jwt|can:)/i,
  /'middleware'\s*=>\s*\[?\s*['"](?:auth|sanctum|jwt)/i,
  // C# — ASP.NET
  /\[\s*Authorize\b/,
]

/**
 * Ce qui atteste une vérification **d'autorisation**, pas seulement
 * d'identité.
 *
 * La distinction porte tout le sujet : savoir *qui* appelle ne dit pas
 * qu'il a le droit d'appeler. Un utilisateur authentifié qui atteint
 * `/admin/users` parce que personne n'a vérifié son rôle est la faille
 * d'API la plus répandue.
 */
const AUTHZ_MARKERS: readonly RegExp[] = [
  /@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed)\b/,
  /\bhas(?:_|)(?:role|authority|permission|any_role|perm)\b/i,
  /\b(?:requireRole|checkRole|checkPermission|hasScope|requireScope|authorizeRoles|can)\s*\(/i,
  /\bIsAdminUser\b|\bDjangoModelPermissions\b|\bDjangoObjectPermissions\b/,
  /\b(?:RolesGuard|PermissionsGuard|PoliciesGuard|AbilityGuard)\b/,
  /@(?:Roles|RequirePermissions|CheckPolicies)\s*\(/,
  /\[\s*Authorize\s*\(\s*Roles\s*=/,
  /->\s*middleware\s*\(\s*\[?\s*['"](?:can:|role:|permission:)/i,
  /\bscopes\s*=\s*\[[^\]]+\]/,
  /\bSecurityScopes\b/,
]

/** Ce qui déclare une route **volontairement** ouverte. */
const PUBLIC_MARKERS: readonly RegExp[] = [
  /\bAllowAny\b/,
  /\bpermission_classes\s*=\s*\[\s*\]/,
  /\bauthentication_classes\s*=\s*\[\s*\]/,
  /@AllowAnonymous\b/,
  /@Public\s*\(\s*\)/,
  /\[\s*AllowAnonymous\s*\]/,
  /@\w*csrf_exempt\b/,
]

/**
 * Authentification posée **globalement**, pour toute l'application.
 *
 * Sa présence dans un fichier change tout : sans elle, chaque route sans
 * décorateur serait signalée « non authentifiée », et un projet qui
 * protège correctement ses routes par un middleware recevrait des
 * dizaines de faux signalements. C'est exactement ce qui fait désinstaller
 * un outil de sécurité.
 */
const GLOBAL_AUTH_MARKERS: readonly RegExp[] = [
  // Express / Koa : `app.use(requireAuth)`
  /\b(?:app|server|router)\s*\.\s*use\s*\(\s*(?:[\w.]*\s*,\s*)?[\w.]*(?:auth|jwt|passport|guard|token|session)/i,
  // FastAPI : `FastAPI(dependencies=[Depends(auth)])`, `APIRouter(dependencies=…)`
  /\b(?:FastAPI|APIRouter)\s*\([^)]*dependencies\s*=\s*\[[^\]]+\]/s,
  // Django REST : réglage global des permissions
  /DEFAULT_PERMISSION_CLASSES['"]?\s*:\s*\[\s*(?!\s*\])[^\]]+\]/,
  /DEFAULT_AUTHENTICATION_CLASSES['"]?\s*:\s*\[\s*(?!\s*\])[^\]]+\]/,
  // NestJS : garde globale
  /\bAPP_GUARD\b|\buseGlobalGuards\s*\(/,
  // Spring : chaîne de filtres qui exige une authentification
  /\.\s*anyRequest\s*\(\s*\)\s*\.\s*authenticated\s*\(\s*\)/,
  /@EnableWebSecurity\b|@EnableGlobalMethodSecurity\b|@EnableMethodSecurity\b/,
  // Laravel : groupe de routes protégé
  /Route\s*::\s*middleware\s*\(\s*\[?\s*['"](?:auth|sanctum|jwt)/i,
  // ASP.NET : filtre global
  /\bAuthorizeFilter\b|\bRequireAuthorization\s*\(/,
]

/** Le fichier pose-t-il une authentification pour toutes ses routes ? */
export function hasGlobalAuth(text: string): { found: boolean; evidence: string } {
  for (const pattern of GLOBAL_AUTH_MARKERS) {
    const match = pattern.exec(text)
    if (match) {
      return { found: true, evidence: condense(match[0]) }
    }
  }
  return { found: false, evidence: '' }
}

function firstMatch(
  haystack: string,
  patterns: readonly RegExp[]
): string | null {
  for (const pattern of patterns) {
    const match = pattern.exec(haystack)
    if (match) {
      return condense(match[0])
    }
  }
  return null
}

// --------------------------------------------------------------------------
// Déclarations de routes, par framework
// --------------------------------------------------------------------------

interface RoutePattern {
  readonly framework: ApiFramework
  readonly pattern: RegExp
  /** Extrait méthode et chemin d'une correspondance. */
  readonly read: (match: RegExpExecArray) => { method: string; path: string }
}

const HTTP_VERBS = 'get|post|put|patch|delete|head|options|trace'

const ROUTE_PATTERNS: readonly RoutePattern[] = [
  // --- Python -----------------------------------------------------------
  //
  // FastAPI / Starlette : `@app.get("/users/{id}")`, `@router.post("/x")`
  {
    framework: 'fastapi',
    pattern: new RegExp(`@\\s*[\\w.]+\\.(${HTTP_VERBS})\\s*\\(\\s*['"\`]([^'"\`]*)`, 'i'),
    read: (match) => ({
      method: (match[1] ?? 'ANY').toUpperCase(),
      path: match[2] ?? '',
    }),
  },
  // FastAPI : `@app.api_route("/x", methods=["POST"])`
  {
    framework: 'fastapi',
    pattern: /@\s*[\w.]+\.api_route\s*\(\s*['"`]([^'"`]*)['"`][^)]*methods\s*=\s*\[([^\]]*)\]/i,
    read: (match) => ({
      method: firstVerb(match[2] ?? ''),
      path: match[1] ?? '',
    }),
  },
  // Flask : `@app.route("/x", methods=["POST"])`
  {
    framework: 'flask',
    pattern: /@\s*[\w.]+\.route\s*\(\s*['"`]([^'"`]*)['"`]([^)]*)/i,
    read: (match) => ({
      method: methodsFromFlask(match[2] ?? ''),
      path: match[1] ?? '',
    }),
  },
  // Django : `path("admin/", view)`, `re_path(r"^x$", view)`, `url(...)`
  {
    framework: 'django',
    pattern: /\b(?:path|re_path|url)\s*\(\s*r?['"`]([^'"`]*)['"`]\s*,/,
    read: (match) => ({ method: 'ANY', path: match[1] ?? '' }),
  },

  // --- JavaScript / TypeScript -----------------------------------------
  //
  // Express / Koa / Fastify : `app.get('/x', handler)`
  {
    framework: 'express',
    pattern: new RegExp(
      `\\b(?:app|router|server|fastify|api)\\s*\\.\\s*(${HTTP_VERBS}|all)\\s*\\(\\s*['"\`]([^'"\`]*)`,
      'i'
    ),
    read: (match) => ({
      method: (match[1] ?? 'ANY').toUpperCase() === 'ALL' ? 'ANY' : (match[1] ?? 'ANY').toUpperCase(),
      path: match[2] ?? '',
    }),
  },
  // Fastify déclaratif : `fastify.route({ method: 'POST', url: '/x' })`
  {
    framework: 'express',
    pattern: /\bmethod\s*:\s*['"`](\w+)['"`][^}]*\burl\s*:\s*['"`]([^'"`]*)/i,
    read: (match) => ({
      method: (match[1] ?? 'ANY').toUpperCase(),
      path: match[2] ?? '',
    }),
  },
  // NestJS : `@Get('x')`, `@Post()`
  {
    framework: 'nestjs',
    pattern: new RegExp(`@\\s*(${HTTP_VERBS})\\s*\\(\\s*['"\`]?([^'"\`)]*)`, 'i'),
    read: (match) => ({
      method: (match[1] ?? 'ANY').toUpperCase(),
      path: (match[2] ?? '').trim(),
    }),
  },

  // --- Java -------------------------------------------------------------
  //
  // Spring : `@GetMapping("/x")`, `@RequestMapping(value="/x", method=POST)`
  {
    framework: 'spring',
    pattern: /@\s*(Get|Post|Put|Patch|Delete)Mapping\s*\(\s*(?:value\s*=\s*)?['"]?([^'")\s,]*)/,
    read: (match) => ({
      method: (match[1] ?? 'ANY').toUpperCase(),
      path: match[2] ?? '',
    }),
  },
  {
    framework: 'spring',
    pattern: /@\s*RequestMapping\s*\(([^)]*)\)/,
    read: (match) => ({
      method: methodFromSpring(match[1] ?? ''),
      path: pathFromSpring(match[1] ?? ''),
    }),
  },

  // --- PHP --------------------------------------------------------------
  //
  // Laravel : `Route::get('/x', ...)`, `Route::match(['get','post'], ...)`
  {
    framework: 'laravel',
    pattern: new RegExp(`Route\\s*::\\s*(${HTTP_VERBS}|any)\\s*\\(\\s*['"]([^'"]*)`, 'i'),
    read: (match) => ({
      method: (match[1] ?? 'ANY').toUpperCase() === 'ANY' ? 'ANY' : (match[1] ?? 'ANY').toUpperCase(),
      path: match[2] ?? '',
    }),
  },

  // --- C# ---------------------------------------------------------------
  //
  // ASP.NET : `[HttpGet("x")]`, `[Route("api/x")]`
  {
    framework: 'aspnet',
    pattern: /\[\s*Http(Get|Post|Put|Patch|Delete)\s*(?:\(\s*['"]([^'"]*)['"]\s*\))?\s*\]/,
    read: (match) => ({
      method: (match[1] ?? 'ANY').toUpperCase(),
      path: match[2] ?? '',
    }),
  },
  // Minimal API : `app.MapGet("/x", handler)`
  {
    framework: 'aspnet',
    pattern: /\b[\w.]+\s*\.\s*Map(Get|Post|Put|Patch|Delete)\s*\(\s*['"]([^'"]*)/,
    read: (match) => ({
      method: (match[1] ?? 'ANY').toUpperCase(),
      path: match[2] ?? '',
    }),
  },
]

/**
 * Extensions dont on tente la lecture, par famille.
 *
 * Sert à n'appliquer que les motifs plausibles : chercher `Route::get`
 * dans un fichier Python coûte du temps et peut produire une
 * correspondance fortuite dans une chaîne.
 */
const FRAMEWORKS_BY_EXTENSION: Readonly<Record<string, readonly ApiFramework[]>> = {
  '.py': ['fastapi', 'flask', 'django'],
  '.js': ['express', 'nestjs'],
  '.jsx': ['express', 'nestjs'],
  '.mjs': ['express', 'nestjs'],
  '.cjs': ['express', 'nestjs'],
  '.ts': ['express', 'nestjs'],
  '.tsx': ['express', 'nestjs'],
  '.java': ['spring'],
  '.kt': ['spring'],
  '.php': ['laravel'],
  '.cs': ['aspnet'],
}

/** Familles de motifs applicables à ce fichier. Vide = rien à chercher. */
export function frameworksForPath(relativePath: string): readonly ApiFramework[] {
  const dot = relativePath.lastIndexOf('.')
  if (dot < 0) {
    return []
  }
  return FRAMEWORKS_BY_EXTENSION[relativePath.slice(dot).toLowerCase()] ?? []
}

// --------------------------------------------------------------------------
// Parcours
// --------------------------------------------------------------------------

/** Lignes examinées avant et après une déclaration pour y chercher l'auth. */
const WINDOW_BEFORE = 6
const WINDOW_AFTER = 8

/**
 * Relève les routes déclarées dans ce fichier.
 *
 * `lines` est fourni par l'appelant, qui a déjà décidé que ce fichier
 * pouvait être lu et l'a découpé une seule fois.
 */
export function detectRoutes(
  relativePath: string,
  lines: readonly string[]
): DetectedRoute[] {
  const families = frameworksForPath(relativePath)
  if (families.length === 0) {
    return []
  }

  const applicable = ROUTE_PATTERNS.filter((candidate) =>
    families.includes(candidate.framework)
  )
  const routes: DetectedRoute[] = []

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? ''
    if (line.length > 600 || isComment(line)) {
      // Une ligne très longue est du code généré ou minifié ; un
      // commentaire décrit une route, il n'en expose pas.
      continue
    }

    for (const candidate of applicable) {
      const match = candidate.pattern.exec(line)
      if (!match) {
        continue
      }

      const window = windowAround(lines, index)
      const authEvidence = firstMatch(window, AUTH_MARKERS)
      const authzEvidence = firstMatch(window, AUTHZ_MARKERS)
      const publicEvidence = firstMatch(window, PUBLIC_MARKERS)
      const read = candidate.read(match)

      routes.push({
        framework: candidate.framework,
        method: read.method,
        path: read.path,
        line: index + 1,
        evidence: condense(line),
        authenticated: authEvidence !== null,
        authEvidence,
        authorized: authzEvidence !== null,
        authzEvidence,
        explicitlyPublic: publicEvidence !== null,
        publicEvidence,
      })
      // Une ligne ne déclare qu'une route : le premier motif qui
      // correspond gagne, et les suivants ne la redéclarent pas.
      break
    }
  }

  return routes
}

/**
 * Texte examiné autour d'une déclaration.
 *
 * Volontairement généreux vers le bas : en Python, l'authentification est
 * dans la signature de la fonction, qui suit le décorateur et peut
 * s'étaler sur plusieurs lignes.
 */
function windowAround(lines: readonly string[], index: number): string {
  const from = Math.max(0, index - WINDOW_BEFORE)
  const to = Math.min(lines.length, index + WINDOW_AFTER + 1)
  return lines.slice(from, to).join('\n')
}

/** La ligne est-elle un commentaire ? Une route commentée n'expose rien. */
function isComment(line: string): boolean {
  const trimmed = line.trimStart()
  return (
    trimmed.startsWith('#') ||
    trimmed.startsWith('//') ||
    trimmed.startsWith('*') ||
    trimmed.startsWith('/*')
  )
}

/** Premier verbe d'une liste `["GET", "POST"]`. */
function firstVerb(raw: string): string {
  const match = /['"`](\w+)['"`]/.exec(raw)
  return match?.[1]?.toUpperCase() ?? 'ANY'
}

/**
 * Méthodes déclarées par un `@app.route`.
 *
 * Flask accepte plusieurs méthodes ; on retient celle qui **modifie**,
 * parce que c'est elle qui porte le risque. Sans `methods=`, Flask
 * n'expose que `GET`.
 */
function methodsFromFlask(rest: string): string {
  const match = /methods\s*=\s*\[([^\]]*)\]/i.exec(rest)
  if (!match) {
    return 'GET'
  }
  const declared = [...(match[1] ?? '').matchAll(/['"`](\w+)['"`]/g)].map((item) =>
    (item[1] ?? '').toUpperCase()
  )
  return declared.find((method) => STATE_CHANGING.has(method)) ?? declared[0] ?? 'GET'
}

function methodFromSpring(inner: string): string {
  const match = /RequestMethod\s*\.\s*(\w+)/.exec(inner)
  return match?.[1]?.toUpperCase() ?? 'ANY'
}

function pathFromSpring(inner: string): string {
  const match = /(?:value|path)\s*=\s*['"]([^'"]*)/.exec(inner) ?? /['"]([^'"]*)/.exec(inner)
  return match?.[1] ?? ''
}

/** Extrait court et sur une seule ligne, pour la preuve affichée. */
export function condense(value: string): string {
  return value.replace(/\s+/g, ' ').trim().slice(0, 160)
}
