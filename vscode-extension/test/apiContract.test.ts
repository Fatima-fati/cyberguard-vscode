/**
 * Côté extension du test de contrat (audit §25.3, priorité P0).
 *
 * Le risque fermé ici : `backendClient.ts` / `projectTypes.ts` (interfaces
 * TypeScript) et les modèles Pydantic du backend décrivent le **même**
 * contrat en deux endroits, sans lien mécanique. Une divergence ne se
 * manifeste qu'à l'exécution, chez l'utilisateur, sous la forme d'un champ
 * vide ou d'un affichage de travers — la classe de bug la plus coûteuse
 * parce qu'elle est silencieuse.
 *
 * `contract/api-contract.json` fait autorité. Deux tests le lisent :
 *
 *     backend/tests/test_api_contract.py         → schéma OpenAPI
 *     vscode-extension/test/apiContract.test.ts  → ce fichier
 *
 * Une divergence d'un côté **ou** de l'autre fait échouer un build.
 *
 * Comment un test TypeScript vérifie des types
 * --------------------------------------------
 *
 * Les interfaces n'existent plus à l'exécution. On vérifie donc autrement :
 *
 * 1. **à la compilation** — des objets littéraux typés avec les interfaces
 *    réelles. Un champ retiré ou renommé fait échouer `tsc`, donc `npm run
 *    build`, avant même que ce test ne tourne ;
 * 2. **à l'exécution** — les clés de ces mêmes objets sont comparées à la
 *    liste du contrat. Un champ ajouté au contrat mais absent des types
 *    fait échouer ici.
 *
 * Les deux mécanismes sont nécessaires : le premier attrape les
 * suppressions, le second les oublis.
 */

import assert from 'node:assert/strict'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { describe, it } from 'node:test'

import type { CodeHealth, ScanPayload } from '../src/api/backendClient'
import type {
  ClassifiedFile,
  DetectedFramework,
  DetectedLanguage,
  FileStatistics,
  GitMetadata,
  IndexedFile,
  ManifestEvidence,
  ProjectDiscoverSubmission,
  ProjectIndexSubmission,
  ProjectRegistration,
  ProjectSecurityContext,
} from '../src/project/projectTypes'
import type {
  ApiFindingSubmission,
  ApiScanSubmission,
  ApiStatistics,
  DependencyInventorySubmission,
  DependencyRecord,
  DependencyStatistics,
  EcosystemSummary,
  SecretFindingSubmission,
  SecretScanSubmission,
  SecretStatistics,
  SecurityEngineHealth,
  SecurityFinding,
  VulnerabilityStatistics,
} from '../src/security/securityTypes'
import type {
  AiFindingCounts,
  SecurityAiHealth,
  SecurityAiSummaryRequest,
  SecurityChatRequest,
  SecurityChatResponse,
  SecurityChatTurn,
  SecurityFindingAiAnalysis,
  SecurityFindingsAiSummary,
  SecurityFixProposal,
  SecurityFixRequest,
} from '../src/ai/aiTypes'
import type {
  CiBlockingFinding,
  CiCheckResult,
  CiPolicyRequest,
  PostureArea,
  PostureCoverage,
  SecurityPosture,
} from '../src/posture/postureTypes'

// --------------------------------------------------------------------------
// Le contrat
// --------------------------------------------------------------------------

interface ModelContract {
  purpose?: string
  required?: string[]
  forbidden?: string[]
}

interface EndpointContract {
  purpose?: string
  authenticated?: boolean
  request?: { model: string } & ModelContract
  response?: { model: string } & ModelContract
}

interface Contract {
  version: string
  endpoints: Record<string, EndpointContract>
  models: Record<string, ModelContract>
  invariants: string[]
}

const CONTRACT_PATH = path.resolve(__dirname, '..', '..', 'contract', 'api-contract.json')

function loadContract(): Contract {
  assert.ok(fs.existsSync(CONTRACT_PATH), `contrat introuvable : ${CONTRACT_PATH}`)
  return JSON.parse(fs.readFileSync(CONTRACT_PATH, 'utf8')) as Contract
}

const contract = loadContract()

// --------------------------------------------------------------------------
// Échantillons typés
// --------------------------------------------------------------------------
//
// Chaque objet est annoté avec l'interface réelle et renseigne **tous** ses
// champs. `tsc` refuse donc un champ inconnu comme un champ manquant : la
// première moitié de la vérification est faite par le compilateur, avant
// que ce fichier ne s'exécute.

const codeHealth: Required<CodeHealth> = {
  status: 'ok',
  analysis_enabled: true,
  ai_enabled: false,
  rules_version: '1.0.1',
  rules_count: 18,
  api_version: '1.0.0',
  max_content_bytes: 400_000,
  database: 'ok',
  auth_required: true,
  project_context_enabled: true,
  project_security_enabled: true,
}

const scanPayload: Required<ScanPayload> = {
  file_path: 'src/app.py',
  language: 'python',
  content: '',
  content_hash: 'a'.repeat(64),
  workspace: null,
  project_uid: null,
  ai_enrichment: false,
}

const indexedFile: Required<IndexedFile> = {
  path: 'src/app.py',
  content_hash: null,
  size: 0,
  mtime: null,
}

const manifestEvidence: Required<ManifestEvidence> = {
  path: 'package.json',
  ecosystem: 'npm',
  dependency_names: [],
}

const gitMetadata: Required<GitMetadata> = {
  detected: false,
  remote_host: null,
}

const classifiedFile: Required<ClassifiedFile> = {
  path: '.env',
  kind: 'sensitive',
  type: 'environment-secrets',
  reason: 'peut contenir des identifiants',
}

const detectedLanguage: Required<DetectedLanguage> = {
  language: 'python',
  file_count: 1,
  share: 100,
  analysis_supported: true,
}

const detectedFramework: Required<DetectedFramework> = {
  framework: 'FastAPI',
  evidence: 'dépendance « fastapi » déclarée',
  source: 'requirements.txt',
  confidence: 0.9,
}

const fileStatistics: Required<FileStatistics> = {
  discovered: 0,
  indexed: 0,
  source: 0,
  manifests: 0,
  configuration: 0,
  tests: 0,
  sensitive: 0,
  truncated: false,
}

// --- Sécurité projet (phase 2) ---------------------------------------
//
// Mêmes règles que ci-dessus : chaque objet est annoté avec l'interface
// réelle et renseigne **tous** ses champs, pour que `tsc` refuse un champ
// inconnu comme un champ manquant.

const secretStatistics: Required<SecretStatistics> = {
  total: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  files_with_secrets: 0,
  scanned_files: 0,
  truncated: false,
  engine: 'secret-scanner@1.0.0',
  last_scan: null,
}

const dependencyStatistics: Required<DependencyStatistics> = {
  total: 0,
  direct: 0,
  transitive: 0,
  vulnerable: 0,
  unverified: 0,
  manifests_read: 0,
  truncated: false,
  last_inventory: null,
}

const ecosystemSummary: Required<EcosystemSummary> = {
  ecosystem: 'npm',
  total: 0,
  direct: 0,
  vulnerable: 0,
  verified: 0,
}

const vulnerabilityStatistics: Required<VulnerabilityStatistics> = {
  total: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  packages_affected: 0,
  packages_checked: 0,
  packages_unverified: 0,
  provider: 'osv',
  provider_status: 'disabled',
  provider_status_label: 'Vérification désactivée',
  message: 'Vérification des vulnérabilités désactivée.',
  conclusive: false,
  last_check: null,
}

const securityFinding: Required<SecurityFinding> = {
  id: 'abc',
  project_uid: 'uid',
  category: 'SECRET',
  severity: 'CRITICAL',
  severity_label: 'CRITIQUE',
  confidence: 'HIGH',
  confidence_label: 'ÉLEVÉE',
  category_label: 'Secret exposé',
  title: "Clé d'API OpenAI écrite en dur",
  description: '',
  file: 'backend/config.py',
  line_start: 24,
  line_end: 24,
  // La preuve est expurgée : c'est la seule forme qu'un finding puisse
  // porter, et un test d'invariant plus bas le vérifie.
  evidence: 'OpenAI API key detected: sk-proj-********',
  remediation: '',
  references: ['CWE-798'],
  detection_engine: 'secret-scanner',
  status: 'open',
  status_label: 'Ouvert',
  created_at: '2026-01-01T00:00:00Z',
}

const secretFindingSubmission: Required<SecretFindingSubmission> = {
  rule_id: 'secret.openai_api_key',
  file_path: 'backend/config.py',
  line: 24,
  column: 12,
  secret_type: 'openai_api_key',
  severity: 'CRITICAL',
  confidence: 'HIGH',
  evidence_redacted: 'OpenAI API key detected: sk-proj-********',
  title: '',
  description: '',
  remediation: '',
  references: [],
}

const secretScanSubmission: Required<SecretScanSubmission> = {
  findings: [],
  scanned_files: 0,
  skipped_files: 0,
  engine: 'secret-scanner',
  engine_version: '1.0.0',
  truncated: false,
  warnings: [],
}

const dependencyRecord: Required<DependencyRecord> = {
  name: 'express',
  ecosystem: 'npm',
  version: '4.18.2',
  direct: true,
  manifest: 'package.json',
  source: 'manifest',
}

const dependencyInventorySubmission: Required<DependencyInventorySubmission> = {
  dependencies: [],
  manifests_read: 0,
  truncated: false,
  warnings: [],
  inventory_version: '1.0.0',
  check_vulnerabilities: true,
}

const apiFindingSubmission: Required<ApiFindingSubmission> = {
  rule_id: 'API-AUTH-001',
  file_path: 'src/routes.py',
  line: 12,
  issue_type: 'unauthenticated_endpoint',
  endpoint: '/admin/users',
  http_method: 'POST',
  framework: 'fastapi',
  severity: 'HIGH',
  confidence: 'MEDIUM',
  evidence: '@app.post("/admin/users")',
  title: 'Endpoint sans authentification apparente',
  description: '',
  remediation: '',
  references: ['CWE-306'],
}

const apiScanSubmission: Required<ApiScanSubmission> = {
  findings: [],
  scanned_files: 0,
  endpoints_detected: 0,
  engine: 'api-scanner',
  engine_version: '1.0.0',
  truncated: false,
  warnings: [],
}

const apiStatistics: Required<ApiStatistics> = {
  total: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  endpoints_detected: 0,
  unauthenticated_endpoints: 0,
  files_with_findings: 0,
  scanned_files: 0,
  truncated: false,
  engine: '',
  last_scan: null,
}

const securityEngineHealth: Required<SecurityEngineHealth> = {
  status: 'ok',
  secret_detection_enabled: true,
  dependency_inventory_enabled: true,
  vulnerability_check_enabled: true,
  api_security_enabled: true,
  ai_assistant_enabled: false,
  vulnerability_provider: 'osv',
  supported_ecosystems: ['npm'],
  requires_wazuh: false,
}

// --- Assistant IA de sécurité (phase 6) --------------------------------
//
// Mêmes règles : chaque objet renseigne tous les champs de l'interface
// réelle. Le contrat interdit en plus `severity`, `risk_score` et `status`
// sur les sorties d'IA : la vérification des champs interdits plus bas
// échoue si l'un d'eux apparaît dans ces types.

const aiFindingCounts: Required<AiFindingCounts> = {
  total: 1,
  critical: 0,
  high: 0,
  medium: 1,
  low: 0,
  by_category: { SECRET: 1 },
}

const securityAiHealth: Required<SecurityAiHealth> = {
  status: 'ok',
  available: true,
  chat_available: true,
  fix_available: true,
  provider_configured: true,
  assistant_enabled: true,
  chat_enabled: true,
  model: 'gpt-4o-mini',
  reason: '',
  disclaimer: 'Explication générée par une IA.',
  max_context_findings: 25,
  modifies_findings: false,
  modifies_severity: false,
  requires_wazuh: false,
}

const securityFindingAiAnalysis: Required<SecurityFindingAiAnalysis> = {
  finding_id: 'abc',
  project_uid: 'uid',
  ai_generated: true,
  disclaimer: 'Explication générée par une IA.',
  model: 'gpt-4o-mini',
  analyzed_at: '2026-01-01T00:00:00Z',
  cached: false,
  category: 'SECRET',
  deterministic_severity: 'MEDIUM',
  deterministic_confidence: 'MEDIUM',
  deterministic_title: "Clé d'API écrite en dur",
  deterministic_remediation: '',
  detection_engine: 'secret-scanner',
  file: 'backend/config.py',
  line: 24,
  explanation: 'Une clé écrite en dur.',
  why_it_matters: '',
  project_impact: '',
  evidence_interpretation: '',
  recommendation: '',
  remediation_steps: [],
  secure_example: '',
  secure_example_language: '',
  related_concepts: [],
  developer_summary: '',
  insufficient_context: false,
  missing_information: [],
  confidence: 0.8,
  project_context_available: true,
  related_findings_considered: 0,
}

// --- Remédiation assistée (phase 7) -----------------------------------

const securityFixRequest: Required<SecurityFixRequest> = {
  file_path: 'backend/config.py',
  content_hash: 'a'.repeat(64),
  language: 'python',
  target_line: 7,
  excerpt_start_line: 1,
  excerpt_lines: ['import os', '    KEY = "sk-proj-********"'],
}

const securityFixProposal: Required<SecurityFixProposal> = {
  finding_id: 'abc',
  project_uid: 'uid',
  kind: 'security',
  ai_generated: true,
  disclaimer: 'Modification proposée par une IA.',
  model: 'gpt-4o-mini',
  generated_at: '2026-01-01T00:00:00Z',
  category: 'SECRET',
  deterministic_severity: 'CRITICAL',
  deterministic_title: "Clé d'API écrite en dur",
  available: true,
  refusal: '',
  file: 'backend/config.py',
  base_content_hash: 'a'.repeat(64),
  start_line: 7,
  end_line: 7,
  replacement_lines: ['    KEY = os.environ["OPENAI_API_KEY"]'],
  explanation: '',
  reason: '',
  warnings: [],
  manual_steps: [],
}

// --- Posture et CI/CD (phase 8) -----------------------------------------

const postureCounts = { total: 0, critical: 0, high: 0, medium: 0, low: 0 }

const postureArea: Required<PostureArea> = {
  area: 'secrets',
  state: 'not_analyzed',
  coverage: 'not_analyzed',
  findings: null,
  last_scan: null,
  metrics: {},
  warnings: [],
}

const postureCoverage: Required<PostureCoverage> = {
  context_available: false,
  files_discovered: 0,
  files_indexed: 0,
  index_truncated: false,
  sensitive_files: 0,
  unsupported_languages: [],
  vulnerability_provider: '',
  vulnerability_provider_status: 'disabled',
  vulnerability_check_conclusive: false,
  vulnerability_message: '',
  last_discovery: null,
}

const securityPosture: Required<SecurityPosture> = {
  project_uid: 'uid',
  project_name: 'App',
  generated_at: '2026-01-01T00:00:00Z',
  analysis: 'not_analyzed',
  findings: postureCounts,
  areas: [postureArea],
  coverage: postureCoverage,
  history: { available: false, message: 'Historique insuffisant', oldest_open_finding: null, newest_open_finding: null },
  ai_generated: false,
  requires_ai: false,
  requires_wazuh: false,
}

const ciPolicyRequest: Required<CiPolicyRequest> = {
  mode: 'warn',
  fail_on: [],
  warn_on: [],
}

const ciBlockingFinding: Required<CiBlockingFinding> = {
  id: 'abc',
  area: 'secrets',
  category: 'SECRET',
  severity: 'CRITICAL',
  title: 'Clé écrite en dur',
  file: 'src/config.py',
  line: 3,
}

const ciCheckResult: Required<CiCheckResult> = {
  schema_version: '1.0',
  project: { project_uid: 'uid', project_name: 'App' },
  generated_at: '2026-01-01T00:00:00Z',
  policy: { mode: 'warn', fail_on: [], warn_on: [] },
  status: 'passed',
  exit_decision: 'pass',
  exit_code: 0,
  analysis: 'complete',
  counts: postureCounts,
  counts_by_area: { secrets: 0, git: null },
  conditions: [],
  reasons: [],
  incomplete_areas: [],
  unsupported_languages: [],
  vulnerability_provider_status: 'available',
  vulnerability_check_conclusive: true,
  blocking_findings: [ciBlockingFinding],
  requires_ai: false,
  requires_wazuh: false,
}

const securityAiSummaryRequest: Required<SecurityAiSummaryRequest> = {
  finding_ids: [],
}

const securityFindingsAiSummary: Required<SecurityFindingsAiSummary> = {
  project_uid: 'uid',
  ai_generated: true,
  disclaimer: 'Explication générée par une IA.',
  model: 'gpt-4o-mini',
  analyzed_at: '2026-01-01T00:00:00Z',
  summary: 'Résumé.',
  themes: [],
  relationships: [],
  priority_order: [],
  insufficient_context: false,
  missing_information: [],
  findings_considered: 1,
  findings_available: 1,
  truncated: false,
  severity_counts: aiFindingCounts,
  project_context_available: true,
}

const securityChatTurn: Required<SecurityChatTurn> = {
  role: 'user',
  message: 'Bonjour',
}

const securityChatRequest: Required<SecurityChatRequest> = {
  question: 'Quels secrets ?',
  history: [securityChatTurn],
  finding_id: null,
}

const securityChatResponse: Required<SecurityChatResponse> = {
  project_uid: 'uid',
  ai_generated: true,
  disclaimer: 'Explication générée par une IA.',
  model: 'gpt-4o-mini',
  answered_at: '2026-01-01T00:00:00Z',
  question: 'Quels secrets ?',
  answer: 'Un secret.',
  insufficient_context: false,
  missing_information: [],
  related_concepts: [],
  findings_considered: 1,
  findings_available: 1,
  truncated: false,
  project_context_available: true,
  history_turns_used: 1,
}

const projectContext: Required<ProjectSecurityContext> = {
  project_uid: 'uid',
  project_name: 'App',
  root_hash: 'a'.repeat(64),
  status: 'ready',
  project_types: [],
  primary_language: null,
  languages: [],
  frameworks: [],
  file_statistics: fileStatistics,
  manifests: [],
  important_files: [],
  configuration_files: [],
  security_sensitive_files: [],
  git_repository_detected: false,
  git_remote_host: null,
  secret_statistics: secretStatistics,
  api_statistics: apiStatistics,
  dependency_statistics: dependencyStatistics,
  dependency_ecosystems: [ecosystemSummary],
  vulnerability_statistics: vulnerabilityStatistics,
  warnings: [],
  last_discovery: null,
  discovery_version: '1.0.0',
}

const projectRegistration: Required<ProjectRegistration> = {
  project_uid: 'uid',
  project_name: 'App',
  root_hash: 'a'.repeat(64),
  status: 'discovery',
  known: false,
  last_discovery: null,
}

const discoverSubmission: Required<ProjectDiscoverSubmission> = {
  root_hash: 'a'.repeat(64),
  project_name: 'App',
  discovery_version: '1.0.0',
}

const indexSubmission: Required<ProjectIndexSubmission> = {
  files: [],
  manifests: [],
  git: gitMetadata,
  discovered_count: 0,
  truncated: false,
  warnings: [],
  discovery_version: '1.0.0',
}

/** Modèles de l'assistant IA (phase 6), vérifiés mot à mot ailleurs. */
const AI_MODELS: ReadonlySet<string> = new Set([
  'AiFindingCounts',
  'SecurityAiHealth',
  'SecurityFindingAiAnalysis',
  'SecurityAiSummaryRequest',
  'SecurityFindingsAiSummary',
  'SecurityChatTurn',
  'SecurityChatRequest',
  'SecurityChatResponse',
  // Phase 7. `SecurityFixRequest.excerpt_lines` est l'objet même de la
  // route, comme `CodeScanRequest.content` : un extrait borné, expurgé,
  // jamais persisté. Ses champs interdits sont vérifiés par le contrat.
  'SecurityFixRequest',
  'SecurityFixProposal',
  // Phase 8. `PostureCoverage.context_available` contient « text » sans
  // rien porter d'un fichier ; ces modèles sont vérifiés mot à mot par
  // `posture.test.ts`, et leurs listes `forbidden` interdisent preuve,
  // chemin absolu et score.
  'SecurityPosture',
  'PostureArea',
  'PostureCoverage',
  'CiCheckResult',
  'CiBlockingFinding',
])

/** Échantillon par nom de modèle du contrat. */
const SAMPLES: Record<string, Record<string, unknown>> = {
  CodeHealth: codeHealth,
  CodeScanRequest: scanPayload,
  IndexedFile: indexedFile,
  ManifestEvidence: manifestEvidence,
  GitMetadata: gitMetadata,
  ClassifiedFile: classifiedFile,
  DetectedLanguage: detectedLanguage,
  DetectedFramework: detectedFramework,
  FileStatistics: fileStatistics,
  ProjectSecurityContext: projectContext,
  ProjectRegistration: projectRegistration,
  ProjectDiscoverRequest: discoverSubmission,
  ProjectIndexRequest: indexSubmission,
  SecurityFinding: securityFinding,
  SecretFindingSubmission: secretFindingSubmission,
  SecretScanSubmission: secretScanSubmission,
  SecretStatistics: secretStatistics,
  ApiFindingSubmission: apiFindingSubmission,
  ApiScanSubmission: apiScanSubmission,
  ApiStatistics: apiStatistics,
  DependencyRecord: dependencyRecord,
  DependencyInventorySubmission: dependencyInventorySubmission,
  DependencyStatistics: dependencyStatistics,
  EcosystemSummary: ecosystemSummary,
  VulnerabilityStatistics: vulnerabilityStatistics,
  SecurityEngineHealth: securityEngineHealth,
  AiFindingCounts: aiFindingCounts,
  SecurityAiHealth: securityAiHealth,
  SecurityFindingAiAnalysis: securityFindingAiAnalysis,
  SecurityAiSummaryRequest: securityAiSummaryRequest,
  SecurityFindingsAiSummary: securityFindingsAiSummary,
  SecurityChatTurn: securityChatTurn,
  SecurityChatRequest: securityChatRequest,
  SecurityChatResponse: securityChatResponse,
  SecurityFixRequest: securityFixRequest,
  SecurityFixProposal: securityFixProposal,
  SecurityPosture: securityPosture,
  PostureArea: postureArea,
  PostureCoverage: postureCoverage,
  CiPolicyRequest: ciPolicyRequest,
  CiCheckResult: ciCheckResult,
  CiBlockingFinding: ciBlockingFinding,
}

// --------------------------------------------------------------------------
// Vérifications
// --------------------------------------------------------------------------

describe('contrat d’API — chargement', () => {
  it('le contrat est lisible et bien formé', () => {
    assert.ok(contract.version)
    assert.ok(Object.keys(contract.endpoints).length > 0)
    assert.ok(Object.keys(contract.models).length > 0)
    assert.ok(contract.invariants.length > 0)
  })

  it('le même fichier fait autorité des deux côtés', () => {
    // Le chemin est vérifié : un contrat dupliqué dans l'extension
    // reproduirait exactement le problème qu'il doit résoudre.
    assert.match(CONTRACT_PATH.replace(/\\/g, '/'), /\/contract\/api-contract\.json$/)
  })
})

describe('contrat d’API — champs attendus côté extension', () => {
  for (const [model, definition] of Object.entries(contract.models)) {
    const sample = SAMPLES[model]
    if (!sample) {
      continue
    }

    it(`${model} porte tous les champs du contrat`, () => {
      for (const field of definition.required ?? []) {
        assert.ok(
          field in sample,
          `le champ « ${field} » manque au type TypeScript ${model} : ` +
            'le contrat et l’extension ont divergé.'
        )
      }
    })
  }

  for (const [endpoint, definition] of Object.entries(contract.endpoints)) {
    for (const side of ['request', 'response'] as const) {
      const part = definition[side]
      const sample = part ? SAMPLES[part.model] : undefined
      if (!part || !sample) {
        continue
      }

      it(`${endpoint} — ${side} ${part.model} porte tous les champs`, () => {
        for (const field of part.required ?? []) {
          assert.ok(
            field in sample,
            `${endpoint} : le champ « ${field} » manque à ${part.model}.`
          )
        }
      })
    }
  }
})

describe('contrat d’API — champs interdits', () => {
  for (const [model, definition] of Object.entries(contract.models)) {
    const sample = SAMPLES[model]
    const forbidden = definition.forbidden ?? []
    if (!sample || forbidden.length === 0) {
      continue
    }

    it(`${model} ne porte aucun champ interdit`, () => {
      // Ce ne sont pas des oublis : ce sont des interdits de sécurité,
      // vérifiés à chaque build. Quand une phase suivante aura besoin du
      // contenu d'un fichier, la facilité sera de l'ajouter au type
      // existant ; ce test transforme cette facilité en échec visible.
      for (const field of forbidden) {
        assert.ok(
          !(field in sample),
          `le champ « ${field} » est apparu dans ${model}. Interdit par le ` +
            `contrat : ${definition.purpose ?? ''}`
        )
      }
    })
  }
})

describe('contrat d’API — invariants de sécurité', () => {
  it('aucun type de projet ne porte de contenu de fichier', () => {
    // Balayage par motif, au-delà de la liste nominative : un champ nommé
    // autrement mais de même nature — `raw_text`, `file_body` — serait
    // manqué par une liste fermée.
    const suspects = ['content', 'body', 'text', 'raw', 'excerpt', 'snippet']
    const autorises = new Set(['content_hash'])

    for (const [model, sample] of Object.entries(SAMPLES)) {
      if (model === 'CodeScanRequest' || model === 'CodeHealth') {
        // `CodeScanRequest.content` est le document analysé : c'est l'objet
        // même de la route, et il n'est jamais persisté.
        continue
      }
      if (AI_MODELS.has(model)) {
        // Phase 6 : `insufficient_context` ou `max_context_findings`
        // contiennent « text » sans rien porter d'un fichier. Ces modèles
        // sont vérifiés mot à mot par `securityAi.test.ts`, et leurs
        // listes `forbidden` du contrat interdisent `content`.
        continue
      }
      for (const field of Object.keys(sample)) {
        if (autorises.has(field)) {
          continue
        }
        for (const suspect of suspects) {
          assert.ok(
            !field.toLowerCase().includes(suspect),
            `${model}.${field} ressemble à un champ de contenu.`
          )
        }
      }
    }
  })

  it('aucun type de projet ne porte de chemin absolu', () => {
    const interdits = ['workspace_path', 'root_path', 'absolute_path', 'fs_path']
    for (const [model, sample] of Object.entries(SAMPLES)) {
      for (const field of Object.keys(sample)) {
        assert.ok(
          !interdits.includes(field),
          `${model}.${field} porterait un chemin absolu. Seul root_hash circule.`
        )
      }
    }
  })

  it('le contexte de projet ne porte pas d’URL de remote Git', () => {
    // Une URL de remote complète peut contenir un jeton d'accès. Seul
    // l'hôte traverse.
    assert.ok('git_remote_host' in projectContext)
    assert.ok(!('git_remote_url' in projectContext))
  })

  it('le contexte de projet ne porte aucun score de sécurité', () => {
    // La posture explicable, avec sa couverture, appartient à une phase
    // ultérieure : un chiffre sans son explication serait pris pour un
    // verdict.
    for (const field of ['security_score', 'score', 'grade', 'rating']) {
      assert.ok(!(field in projectContext), `${field} ne doit pas exister encore`)
    }
  })

  it('les statistiques annoncent toujours la troncature', () => {
    // Sans ce champ, une couverture partielle serait affichée comme
    // complète — le mensonge de sécurité que le projet s'interdit.
    assert.ok('truncated' in fileStatistics)
    assert.ok('discovered' in fileStatistics)
    assert.ok('indexed' in fileStatistics)
  })

  it('un framework porte toujours sa preuve', () => {
    // Sans preuve, un framework « détecté » est une affirmation non
    // vérifiable.
    assert.ok('evidence' in detectedFramework)
    assert.ok('source' in detectedFramework)
    assert.ok(detectedFramework.evidence.length > 0)
  })

  it('un fichier sensible porte sa raison, et rien de plus', () => {
    assert.deepEqual(Object.keys(classifiedFile).sort(), [
      'kind',
      'path',
      'reason',
      'type',
    ])
  })

  it('un langage annonce si des règles existent pour lui', () => {
    // Annoncer une couverture inexistante tromperait l'utilisateur sur sa
    // propre exposition.
    assert.ok('analysis_supported' in detectedLanguage)
  })
})

describe('contrat d’API — authentification', () => {
  it('une seule route publique est déclarée', () => {
    const publiques = Object.entries(contract.endpoints)
      .filter(([, definition]) => definition.authenticated === false)
      .map(([endpoint]) => endpoint)

    // Le health du code reste public pour que l'extension puisse
    // distinguer « pas authentifié » de « backend éteint ».
    assert.deepEqual(publiques, ['GET /api/code/health'])
  })

  it('la route publique annonce si l’authentification est exigée', () => {
    assert.ok('auth_required' in codeHealth)
    assert.ok('project_context_enabled' in codeHealth)
  })

  it('toutes les routes de projet sont authentifiées', () => {
    for (const [endpoint, definition] of Object.entries(contract.endpoints)) {
      if (endpoint.includes('/api/project/')) {
        assert.equal(
          definition.authenticated,
          true,
          `${endpoint} doit exiger le jeton : le contexte décrit ` +
            'l’arborescence du projet et ses fichiers sensibles.'
        )
      }
    }
  })
})
