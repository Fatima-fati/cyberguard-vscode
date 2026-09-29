/**
 * Posture de sécurité et contrôle CI/CD, côté extension (phase 8).
 *
 * Miroir de `backend/app/security/posture_schemas.py`, relié par
 * `contract/api-contract.json`.
 *
 * **Aucun score.** `findings: null` signifie « jamais analysé », et aucun
 * chemin de code ne le remplace par 0 : c'est la seule façon de ne pas
 * afficher un feu vert là où personne n'a regardé.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

export type PostureAreaName = 'secrets' | 'dependencies' | 'code' | 'api' | 'git'
export type AreaCoverage = 'not_analyzed' | 'complete' | 'partial' | 'unavailable'
export type AreaState = 'not_analyzed' | 'unavailable' | 'no_findings' | 'findings'
export type OverallAnalysis = 'not_analyzed' | 'partial' | 'complete'

export type CiMode = 'off' | 'warn' | 'block'
export type CiStatus = 'off' | 'passed' | 'warning' | 'blocked'
export type CiCondition =
  | 'critical_findings'
  | 'high_findings'
  | 'secrets_present'
  | 'vulnerable_dependencies'
  | 'analysis_incomplete'
  | 'vulnerability_provider_unavailable'
  | 'unsupported_languages'

export interface PostureCounts {
  total: number
  critical: number
  high: number
  medium: number
  low: number
}

export interface PostureArea {
  area: PostureAreaName
  state: AreaState
  coverage: AreaCoverage
  /** `null` = jamais analysé. Jamais remplacé par 0. */
  findings: PostureCounts | null
  last_scan: string | null
  metrics: Record<string, number>
  warnings: string[]
}

export interface PostureCoverage {
  context_available: boolean
  files_discovered: number
  files_indexed: number
  index_truncated: boolean
  sensitive_files: number
  unsupported_languages: string[]
  vulnerability_provider: string
  vulnerability_provider_status: string
  vulnerability_check_conclusive: boolean
  vulnerability_message: string
  last_discovery: string | null
}

export interface PostureHistory {
  available: boolean
  message: string
  oldest_open_finding: string | null
  newest_open_finding: string | null
}

export interface SecurityPosture {
  project_uid: string
  project_name: string
  generated_at: string
  analysis: OverallAnalysis
  findings: PostureCounts
  areas: PostureArea[]
  coverage: PostureCoverage
  history: PostureHistory
  ai_generated: false
  requires_ai: false
  requires_wazuh: false
}

export interface CiPolicyRequest {
  mode?: CiMode | null
  fail_on?: CiCondition[] | null
  warn_on?: CiCondition[] | null
}

export interface CiPolicy {
  mode: CiMode
  fail_on: CiCondition[]
  warn_on: CiCondition[]
}

export interface CiConditionResult {
  code: CiCondition
  triggered: boolean
  value: number
  action: 'block' | 'warn' | 'ignore'
  message: string
}

export interface CiReason {
  code: CiCondition
  action: 'block' | 'warn'
  message: string
}

export interface CiBlockingFinding {
  id: string
  area: PostureAreaName
  category: string
  severity: string
  title: string
  /** Chemin relatif, ou `null`. Jamais un chemin absolu. */
  file: string | null
  line: number
}

export interface CiProject {
  project_uid: string
  project_name: string
}

export interface CiCheckResult {
  schema_version: string
  project: CiProject
  generated_at: string
  policy: CiPolicy
  status: CiStatus
  exit_decision: 'pass' | 'fail'
  exit_code: number
  analysis: OverallAnalysis
  counts: PostureCounts
  counts_by_area: Record<string, number | null>
  conditions: CiConditionResult[]
  reasons: CiReason[]
  incomplete_areas: string[]
  unsupported_languages: string[]
  vulnerability_provider_status: string
  vulnerability_check_conclusive: boolean
  blocking_findings: CiBlockingFinding[]
  requires_ai: false
  requires_wazuh: false
}

export const CI_CONDITIONS: readonly CiCondition[] = [
  'critical_findings',
  'high_findings',
  'secrets_present',
  'vulnerable_dependencies',
  'analysis_incomplete',
  'vulnerability_provider_unavailable',
  'unsupported_languages',
]

/** Mode lu depuis un réglage : une valeur inconnue retombe sur `warn`. */
export function normalizeCiMode(value: unknown): CiMode {
  return value === 'off' || value === 'block' || value === 'warn' ? value : 'warn'
}
