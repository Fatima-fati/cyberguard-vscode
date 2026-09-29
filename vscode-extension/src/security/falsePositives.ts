/**
 * Contrôle des faux positifs de la détection de secrets.
 *
 * Le problème que ce module résout n'est pas cosmétique. Une liste de
 * signalements critiques où un sur deux est un `YOUR_API_KEY` cesse d'être
 * lue — et le jour où un vrai secret y figure, il passe inaperçu. Le
 * bruit ne dégrade pas seulement le confort : il détruit le signal.
 *
 * Deux traitements, jamais confondus
 * ----------------------------------
 *
 *     REJET            la valeur ne peut pas être un secret
 *                      → `${VAR}`, `<API_KEY>`, `CHANGE_ME`, `xxxxxxxx`
 *
 *     DÉCLASSEMENT     la valeur pourrait en être un, mais le contexte
 *                      invite à la prudence
 *                      → fichier de test, documentation, exemple
 *
 * La distinction porte une décision : un placeholder est **écarté**
 * (l'afficher serait toujours faux), alors qu'une clé dans un fichier de
 * test est **déclassée** (les secrets réels dans les fixtures existent, et
 * les taire serait un angle mort). Rejeter dans le doute reviendrait à
 * choisir le silence — exactement ce qu'un outil de sécurité ne doit pas
 * faire.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import type { Confidence, Severity } from './securityTypes'

// --------------------------------------------------------------------------
// Rejet : ce qui ne peut pas être un secret
// --------------------------------------------------------------------------

/**
 * Formes de substitution.
 *
 * Toutes désignent une valeur à fournir ailleurs : variable
 * d'environnement, gabarit de configuration, interpolation de shell. Aucune
 * n'est la valeur elle-même.
 */
const SUBSTITUTION_PATTERNS: readonly RegExp[] = [
  /^\$\{[^}]*\}$/, //            ${API_KEY}, ${env.KEY}
  /^\$[A-Za-z_][A-Za-z0-9_]*$/, // $API_KEY
  /^\{\{[^}]*\}\}$/, //          {{ api_key }}  (Jinja, Handlebars, Helm)
  /^%[A-Za-z0-9_]+%$/, //        %API_KEY%      (Windows)
  /^<[^>]*>$/, //                <API_KEY>, <your key here>
  /^\[[^\]]*\]$/, //             [API_KEY]
  /^#\{[^}]*\}$/, //             #{api_key}     (Ruby)
  /^:[A-Za-z_][A-Za-z0-9_]*$/, // :api_key      (paramètre nommé)
]

/**
 * Lectures de configuration.
 *
 * La valeur détectée est en réalité un appel qui ira chercher le secret
 * ailleurs. C'est exactement la correction qu'on recommanderait : la
 * signaler serait absurde.
 */
const CONFIGURATION_READS: readonly RegExp[] = [
  /^process\.env\b/i,
  /^import\.meta\.env\b/i,
  /^os\.environ\b/i,
  /^os\.getenv\b/i,
  /^System\.getenv\b/i,
  /^getenv\b/i,
  /^ENV\[/i,
  /^config\b[\s.[(]/i,
  /^settings\b[\s.[(]/i,
  /^secrets?\.[A-Za-z_]/i,
  /^Deno\.env\b/i,
  /^\$_ENV\b/i,
  /^\$_SERVER\b/i,
  /^vault\b[\s.:(]/i,
]

/**
 * Mots qui désignent la place d'un secret plutôt qu'un secret.
 *
 * Comparés sur la valeur **normalisée** (minuscules, séparateurs retirés) :
 * `YOUR_API_KEY`, `your-api-key` et `yourApiKey` sont le même placeholder.
 */
const PLACEHOLDER_WORDS: readonly string[] = [
  'yourapikey',
  'yourkey',
  'yoursecret',
  'yourtoken',
  'yourpassword',
  'yourpasswordhere',
  'myapikey',
  'mysecret',
  'apikeyhere',
  'insertyourkeyhere',
  'replaceme',
  'replacewithyourkey',
  'changeme',
  'changethis',
  'tobereplaced',
  'todo',
  'fixme',
  'placeholder',
  'example',
  'examplekey',
  'examplesecret',
  'sample',
  'samplekey',
  'dummy',
  'dummykey',
  'dummysecret',
  'fake',
  'fakekey',
  'notarealkey',
  'notreal',
  'redacted',
  'hidden',
  'masked',
  'secret',
  'password',
  'apikey',
  'token',
  'value',
  'string',
  'null',
  'none',
  'nil',
  'undefined',
  'empty',
  'unset',
  'default',
  'test',
  'testkey',
  'testsecret',
  'testtoken',
  'testvalue',
  'localhost',
  'anonymous',
]

/** Domaines réservés à la documentation (RFC 2606, RFC 6761). */
const DOCUMENTATION_HOSTS: readonly string[] = [
  'example.com',
  'example.org',
  'example.net',
  'example.edu',
  'localhost',
  'test.invalid',
  '.example',
  '.invalid',
  '.local',
  '.test',
]

/** Retire ce qui ne distingue pas deux écritures d'un même placeholder. */
function normalize(value: string): string {
  return value.toLowerCase().replace(/[\s_\-.]/g, '')
}

/**
 * Cette valeur est-elle une substitution, un gabarit ou un mot-repère ?
 *
 * Réponse `true` = la valeur est **écartée**. Le critère doit donc rester
 * strict : on ne se débarrasse d'une détection que lorsqu'on est certain
 * qu'elle serait fausse.
 */
export function isPlaceholder(value: string): boolean {
  const raw = (value ?? '').trim()
  if (raw.length === 0) {
    return true
  }

  if (SUBSTITUTION_PATTERNS.some((pattern) => pattern.test(raw))) {
    return true
  }
  if (CONFIGURATION_READS.some((pattern) => pattern.test(raw))) {
    return true
  }

  const lowered = raw.toLowerCase()
  if (DOCUMENTATION_HOSTS.some((host) => lowered.includes(host))) {
    return true
  }

  const normalized = normalize(raw)
  if (PLACEHOLDER_WORDS.includes(normalized)) {
    return true
  }
  // `YOUR_…`, `MY_…`, `EXAMPLE_…` en préfixe : la suite ne change rien.
  if (/^(your|my|example|sample|dummy|fake|test|placeholder|changeme|replaceme)/.test(normalized)) {
    return true
  }

  // Un seul caractère répété, ou une suite triviale. Personne ne choisit
  // « xxxxxxxxxxxx » comme clé d'API.
  if (/^(.)\1{5,}$/.test(raw)) {
    return true
  }
  if (/^(0123456789|1234567890|abcdefgh|azerty|qwerty)/i.test(raw)) {
    return true
  }

  return false
}

// --------------------------------------------------------------------------
// Déclassement : ce qui demande de la prudence
// --------------------------------------------------------------------------

/**
 * Chemins où un secret a de bonnes chances d'être fictif.
 *
 * Fictif **n'est pas** inexistant : des clés réelles se retrouvent dans
 * des fixtures et des exemples plus souvent qu'on ne le croit, et c'est
 * précisément là qu'on oublie de les faire tourner. Le finding est donc
 * conservé, avec une confiance abaissée.
 */
const LOW_TRUST_PATH_MARKERS: readonly RegExp[] = [
  /(^|\/)tests?(\/|$)/i,
  /(^|\/)__tests__(\/|$)/i,
  /(^|\/)spec(\/|$)/i,
  /(^|\/)fixtures?(\/|$)/i,
  /(^|\/)mocks?(\/|$)/i,
  /(^|\/)examples?(\/|$)/i,
  /(^|\/)samples?(\/|$)/i,
  /(^|\/)docs?(\/|$)/i,
  /(^|\/)demo(\/|$)/i,
  /\.(test|spec)\.[a-z]+$/i,
  /\.(example|sample|template|dist)$/i,
  /(^|\/)(readme|changelog|contributing)\.md$/i,
]

/** Ce chemin invite-t-il à la prudence ? */
export function isLowTrustPath(relativePath: string): boolean {
  const normalized = (relativePath ?? '').replace(/\\/g, '/')
  return LOW_TRUST_PATH_MARKERS.some((pattern) => pattern.test(normalized))
}

/**
 * Marqueurs de documentation sur la ligne elle-même.
 *
 * Un secret dans un commentaire d'exemple n'a pas le même poids qu'un
 * secret affecté à une variable de configuration.
 */
const DOCUMENTATION_MARKERS = /\b(e\.?g\.?|exemple|example|for instance|par exemple|sample)\b/i

export function looksLikeDocumentation(line: string): boolean {
  const text = (line ?? '').trim()
  const isComment = /^(\/\/|#|\*|--|<!--|;)/.test(text)
  return isComment && DOCUMENTATION_MARKERS.test(text)
}

// --------------------------------------------------------------------------
// Entropie
// --------------------------------------------------------------------------

/**
 * Entropie de Shannon, en bits par caractère.
 *
 * Elle sert à départager ce qu'un motif large ne peut pas trancher :
 * `api_key = "internal"` et `api_key = "aB3xK9pQ7mZ2"` déclenchent la même
 * règle, et seule la seconde ressemble à une clé.
 *
 * Volontairement employée comme **indice de confiance**, jamais comme
 * critère de détection. Une entropie basse abaisse la confiance ; elle ne
 * fait pas apparaître un finding à elle seule, parce qu'un mot de passe
 * faible reste un mot de passe.
 */
export function shannonEntropy(value: string): number {
  const text = value ?? ''
  if (text.length === 0) {
    return 0
  }

  const frequencies = new Map<string, number>()
  for (const character of text) {
    frequencies.set(character, (frequencies.get(character) ?? 0) + 1)
  }

  let entropy = 0
  for (const count of frequencies.values()) {
    const probability = count / text.length
    entropy -= probability * Math.log2(probability)
  }
  return entropy
}

/** En dessous, une valeur ressemble davantage à un mot qu'à une clé. */
export const LOW_ENTROPY_THRESHOLD = 2.6

// --------------------------------------------------------------------------
// Décision
// --------------------------------------------------------------------------

const CONFIDENCE_ORDER: readonly Confidence[] = ['HIGH', 'MEDIUM', 'LOW']

/** Abaisse une confiance d'un cran, sans jamais descendre sous `LOW`. */
export function downgrade(confidence: Confidence, steps = 1): Confidence {
  const index = CONFIDENCE_ORDER.indexOf(confidence)
  const next = Math.min(CONFIDENCE_ORDER.length - 1, Math.max(0, index) + steps)
  return CONFIDENCE_ORDER[next] ?? 'LOW'
}

/**
 * Plafonne la gravité affichée par la confiance de la détection.
 *
 * Mêmes règles que `app.security.secrets.apply_confidence`, côté backend.
 * La duplication est assumée : l'extension doit pouvoir afficher une
 * gravité cohérente avant même que le backend ait répondu, et un test de
 * contrat vérifie que les deux tables concordent.
 *
 * **Une détection de faible confiance ne s'affiche jamais en CRITICAL.**
 */
export function cappedSeverity(severity: Severity, confidence: Confidence): Severity {
  if (confidence === 'LOW') {
    return severity === 'LOW' ? 'LOW' : 'MEDIUM'
  }
  if (confidence === 'MEDIUM' && severity === 'CRITICAL') {
    return 'HIGH'
  }
  return severity
}
