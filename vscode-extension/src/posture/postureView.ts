/**
 * Section « Posture de sécurité » de la vue Project (phase 8).
 *
 * Construit des groupes et des lignes à partir de données **déjà
 * établies** — posture et contrôle CI du backend, bilan Git local, état de
 * la surveillance. Rien n'est calculé ici qui ne soit déjà un fait : aucun
 * score, aucun avis, aucune IA.
 *
 * Deux règles d'affichage :
 *
 * - **« Non analysé » ne s'écrit jamais « 0 ».** Un domaine dont
 *   `findings` vaut `null` affiche son état, pas un nombre ;
 * - **aucune ligne n'est verte.** « Aucun finding » signifie « les moteurs
 *   n'ont rien signalé dans ce qu'ils ont analysé », et la couverture est
 *   affichée juste à côté.
 *
 * Aucune dépendance à `vscode` : les groupes sont des objets simples, que
 * `ui/projectView.ts` transforme en nœuds d'arbre.
 */

import type { GitSecuritySummary } from '../git/changeAttribution'
import { FR } from '../i18n/fr'
import type { MonitorState } from '../monitor/scanQueue'
import type { CiCheckResult, PostureArea, SecurityPosture } from './postureTypes'

const P = FR.posture

export interface PostureRow {
  id: string
  label: string
  value: string
  icon: string
  color?: string | undefined
  tooltip?: string | undefined
}

export interface PostureGroup extends PostureRow {
  children: PostureRow[]
  expanded: boolean
}

export interface PostureInputs {
  readonly posture?: SecurityPosture | undefined
  readonly ci?: CiCheckResult | undefined
  /** Raison pour laquelle la posture n'a pas pu être lue. */
  readonly error?: string | undefined
  /** Bilan Git local (phase 4). Le backend ne le connaît pas. */
  readonly git?: GitSecuritySummary | undefined
  readonly monitoring?: 'off' | MonitorState | undefined
}

/** Valeur affichée pour un domaine. Jamais « 0 » à la place de « non analysé ». */
export function areaValue(area: PostureArea): string {
  if (area.findings === null) {
    return P.state[area.state] ?? P.state.not_analyzed
  }
  const base = area.findings.total === 0 ? P.state.no_findings : P.findingsCount(area.findings.total)
  return area.coverage === 'partial' ? `${base} · ${P.partial}` : base
}

function areaColor(area: PostureArea): string | undefined {
  if (area.findings && (area.findings.critical > 0 || area.findings.high > 0)) {
    return 'charts.red'
  }
  if (area.findings && area.findings.total > 0) {
    return 'charts.orange'
  }
  if (area.coverage === 'partial') {
    return 'charts.yellow'
  }
  return undefined
}

function areaIcon(area: PostureArea): string {
  switch (area.state) {
    case 'findings':
      return 'warning'
    case 'no_findings':
      return area.coverage === 'partial' ? 'info' : 'pass'
    case 'unavailable':
      return 'circle-slash'
    default:
      return 'circle-outline'
  }
}

/** Domaine Git : le bilan local l'emporte sur le « indisponible » du backend. */
function gitRow(area: PostureArea | undefined, git: GitSecuritySummary | undefined): PostureRow {
  const base = { id: 'posture:area:git', label: P.areaNames.git ?? 'Git' }
  if (!git) {
    return {
      ...base,
      value: area ? areaValue(area) : P.state.unavailable ?? '',
      icon: 'source-control',
      tooltip: area?.warnings.join('\n'),
    }
  }
  if (!git.repository) {
    return { ...base, value: P.gitNoRepository, icon: 'circle-outline' }
  }
  if (!git.conclusive) {
    return {
      ...base,
      value: P.gitNotVerified,
      icon: 'circle-outline',
      color: 'charts.yellow',
      tooltip: git.message || undefined,
    }
  }
  if (git.introduced.total > 0) {
    return {
      ...base,
      value: P.gitIntroduced(git.introduced.total),
      icon: 'warning',
      color: git.introduced.critical + git.introduced.high > 0 ? 'charts.red' : 'charts.orange',
    }
  }
  return { ...base, value: P.gitClean, icon: 'source-control' }
}

function when(stamp: string | null | undefined): string {
  if (!stamp) {
    return FR.project.none
  }
  const date = new Date(stamp)
  return Number.isNaN(date.getTime()) ? FR.project.none : date.toLocaleString()
}

/** Groupes de la section, dans l'ordre d'affichage. */
export function postureGroups(inputs: PostureInputs): PostureGroup[] {
  const { posture, ci } = inputs

  if (!posture) {
    if (!inputs.error) {
      return []
    }
    return [
      {
        id: 'posture:overall',
        label: P.title,
        value: P.unavailable(inputs.error),
        icon: 'circle-slash',
        color: 'charts.yellow',
        children: [],
        expanded: false,
      },
    ]
  }

  const analyzed = posture.analysis !== 'not_analyzed'
  const counts = posture.findings
  const severityRow = (key: 'critical' | 'high' | 'medium' | 'low', label: string, color: string): PostureRow => ({
    id: `posture:findings:${key}`,
    label,
    // Aucune analyse : pas de zéro. La ligne dit « non analysé ».
    value: analyzed ? String(counts[key]) : P.analysis.not_analyzed ?? '',
    icon: 'circle-filled',
    color: analyzed && counts[key] > 0 ? color : undefined,
  })

  const overallChildren: PostureRow[] = [
    severityRow('critical', FR.view.severity.critical, 'charts.red'),
    severityRow('high', FR.view.severity.high, 'charts.orange'),
    severityRow('medium', FR.view.severity.medium, 'charts.yellow'),
    severityRow('low', FR.view.severity.low, 'charts.blue'),
    {
      id: 'posture:history',
      label: P.history,
      value: posture.history.available ? '' : P.historyUnavailable,
      icon: 'history',
      tooltip: posture.history.message,
    },
    {
      id: 'posture:last-discovery',
      label: P.lastScan,
      value: when(posture.coverage.last_discovery),
      icon: 'clock',
    },
  ]
  if (inputs.monitoring) {
    overallChildren.push({
      id: 'posture:monitoring',
      label: P.monitoring,
      value: P.monitoringState[inputs.monitoring] ?? inputs.monitoring,
      icon: inputs.monitoring === 'ERROR' ? 'error' : 'eye',
      color: inputs.monitoring === 'ERROR' ? 'charts.red' : undefined,
    })
  }

  const coverage = posture.coverage
  const coverageGroup: PostureGroup = {
    id: 'posture:coverage',
    label: P.coverage,
    value: coverage.index_truncated ? P.partial : '',
    icon: 'files',
    color: coverage.index_truncated ? 'charts.orange' : undefined,
    expanded: false,
    children: [
      {
        id: 'posture:coverage:files',
        label: P.filesAnalyzed,
        value: coverage.context_available
          ? P.filesDetail(coverage.files_indexed, coverage.files_discovered, coverage.index_truncated)
          : P.analysis.not_analyzed ?? '',
        icon: 'files',
        color: coverage.index_truncated ? 'charts.orange' : undefined,
      },
      {
        id: 'posture:coverage:sensitive',
        label: P.sensitiveFiles,
        value: coverage.context_available ? String(coverage.sensitive_files) : P.analysis.not_analyzed ?? '',
        icon: 'lock',
      },
      {
        id: 'posture:coverage:languages',
        label: P.unsupportedLanguages,
        value: coverage.unsupported_languages.length > 0 ? coverage.unsupported_languages.join(', ') : P.none,
        icon: 'symbol-namespace',
        color: coverage.unsupported_languages.length > 0 ? 'charts.yellow' : undefined,
      },
      {
        id: 'posture:coverage:provider',
        label: P.provider,
        value: coverage.vulnerability_provider
          ? `${coverage.vulnerability_provider} · ${coverage.vulnerability_provider_status}`
          : coverage.vulnerability_provider_status,
        icon: 'cloud',
        color: coverage.vulnerability_check_conclusive ? undefined : 'charts.yellow',
        tooltip: coverage.vulnerability_message || undefined,
      },
    ],
  }

  const byName = new Map(posture.areas.map((area) => [area.area, area]))
  const areaRows: PostureRow[] = (['secrets', 'dependencies', 'code', 'api'] as const)
    .map((name) => byName.get(name))
    .filter((area): area is PostureArea => area !== undefined)
    .map((area) => ({
      id: `posture:area:${area.area}`,
      label: P.areaNames[area.area] ?? area.area,
      value: areaValue(area),
      icon: areaIcon(area),
      color: areaColor(area),
      tooltip: area.warnings.length > 0 ? area.warnings.join('\n') : undefined,
    }))
  areaRows.push(gitRow(byName.get('git'), inputs.git))

  const groups: PostureGroup[] = [
    {
      id: 'posture:overall',
      label: P.title,
      value: P.analysis[posture.analysis] ?? posture.analysis,
      icon: posture.analysis === 'complete' ? 'shield' : 'info',
      color: posture.analysis === 'complete' ? undefined : 'charts.yellow',
      tooltip: P.analysisTooltip,
      expanded: true,
      children: overallChildren,
    },
    coverageGroup,
    {
      id: 'posture:areas',
      label: P.areas,
      value: '',
      icon: 'list-tree',
      expanded: true,
      children: areaRows,
    },
  ]

  groups.push(
    ci
      ? {
          id: 'posture:ci',
          label: P.ci,
          value: P.ciStatus[ci.status] ?? ci.status,
          icon: ci.status === 'blocked' ? 'error' : ci.status === 'warning' ? 'warning' : 'workflow',
          color: ci.status === 'blocked' ? 'charts.red' : ci.status === 'warning' ? 'charts.yellow' : undefined,
          expanded: ci.status === 'blocked',
          children: [
            { id: 'posture:ci:policy', label: P.ciPolicy(ci.policy.mode), value: '', icon: 'settings-gear' },
            ...ci.reasons.map((reason, index) => ({
              id: `posture:ci:reason:${index}`,
              label: reason.action === 'block' ? P.ciStatus.blocked ?? '' : P.ciStatus.warning ?? '',
              value: reason.message,
              icon: reason.action === 'block' ? 'error' : 'warning',
              color: reason.action === 'block' ? 'charts.red' : 'charts.yellow',
              tooltip: reason.message,
            })),
          ],
        }
      : {
          id: 'posture:ci',
          label: P.ci,
          value: P.ciUnavailable,
          icon: 'workflow',
          expanded: false,
          children: [],
        }
  )

  return groups
}
