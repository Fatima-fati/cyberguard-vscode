/**
 * Vue « Security » : bandeau de risque et liste des findings.
 *
 * Deux `TreeView` natives dans un conteneur de la barre d'activité — pas
 * de webview, pas de framework, pas de dépendance ajoutée. Les couleurs,
 * les icônes et la typographie viennent du thème de l'utilisateur.
 *
 *     SECURITY
 *     ├── Risk Overview      Critical/High/Medium/Low/Total
 *     └── Findings           CRITICAL ▸ titre · fichier:ligne
 *
 * Les deux vues lisent le même `FindingsStore` et se redessinent sur son
 * événement de changement : la synchronisation avec le scan HTTP, le flux
 * SSE et `GET /api/code/findings` est donc automatique, sans code dédié
 * par source.
 *
 * Aucun contenu utilisateur n'est interprété ici : les libellés passent
 * par `TreeItem`, que VS Code affiche en texte brut.
 */

import * as path from 'node:path'
import * as vscode from 'vscode'

import type { CodeFinding } from '../api/backendClient'
import { FR } from '../i18n/fr'
import {
  FindingsStore,
  SEVERITY_ORDER,
  type RiskOverview,
  type Severity,
  type Unsubscribe,
} from '../state/findingsStore'

// --------------------------------------------------------------------------
// Habillage par gravité
// --------------------------------------------------------------------------

/**
 * Icône et couleur de chaque gravité.
 *
 * Les couleurs sont des `ThemeColor` : elles suivent le thème actif et
 * restent lisibles en clair comme en sombre, contrairement à un code
 * hexadécimal figé.
 */
const SEVERITY_STYLE: Readonly<
  Record<Severity, { icon: string; color: string; label: string }>
> = {
  CRITICAL: {
    icon: 'error',
    color: 'charts.red',
    label: FR.view.severity.critical,
  },
  HIGH: {
    icon: 'warning',
    color: 'charts.orange',
    label: FR.view.severity.high,
  },
  MEDIUM: {
    icon: 'info',
    color: 'charts.yellow',
    label: FR.view.severity.medium,
  },
  LOW: {
    icon: 'circle-outline',
    color: 'charts.blue',
    label: FR.view.severity.low,
  },
}

function themeIcon(name: string, color: string): vscode.ThemeIcon {
  return new vscode.ThemeIcon(name, new vscode.ThemeColor(color))
}

/** `users.py:10` — jamais le chemin absolu du poste de travail. */
function shortLocation(finding: CodeFinding): string {
  const base = path.basename(finding.file_path) || finding.file_path
  return `${base}:${finding.location?.line_start ?? 0}`
}

// --------------------------------------------------------------------------
// Risk Overview
// --------------------------------------------------------------------------

type OverviewRow = { key: keyof RiskOverview; label: string; icon: string; color: string }

const OVERVIEW_ROWS: readonly OverviewRow[] = [
  { key: 'critical', label: FR.view.severity.critical, icon: 'error', color: 'charts.red' },
  { key: 'high', label: FR.view.severity.high, icon: 'warning', color: 'charts.orange' },
  { key: 'medium', label: FR.view.severity.medium, icon: 'info', color: 'charts.yellow' },
  {
    key: 'low',
    label: FR.view.severity.low,
    icon: 'circle-outline',
    color: 'charts.blue',
  },
  { key: 'total', label: FR.view.total, icon: 'shield', color: 'charts.foreground' },
]

export class RiskOverviewProvider
  implements vscode.TreeDataProvider<OverviewRow>, vscode.Disposable
{
  private readonly emitter = new vscode.EventEmitter<void>()
  readonly onDidChangeTreeData = this.emitter.event

  private readonly store: FindingsStore
  private readonly unsubscribe: Unsubscribe

  constructor(store: FindingsStore) {
    this.store = store
    this.unsubscribe = store.onChange(() => this.emitter.fire())
  }

  getTreeItem(row: OverviewRow): vscode.TreeItem {
    const overview = this.store.overview()
    const count = overview[row.key]

    const item = new vscode.TreeItem(row.label, vscode.TreeItemCollapsibleState.None)
    item.description = String(count)
    item.iconPath = themeIcon(row.icon, count > 0 ? row.color : 'disabledForeground')
    item.tooltip = `${row.label} : ${count}`
    item.contextValue = 'wazuhSecurity.overviewRow'
    return item
  }

  getChildren(element?: OverviewRow): OverviewRow[] {
    // Liste plate : les compteurs n'ont pas d'enfants.
    return element ? [] : [...OVERVIEW_ROWS]
  }

  dispose(): void {
    this.unsubscribe()
    this.emitter.dispose()
  }
}

// --------------------------------------------------------------------------
// Findings
// --------------------------------------------------------------------------

/** Groupe de gravité : `CRITICAL`, `HIGH`… */
export interface SeverityNode {
  kind: 'severity'
  severity: Severity
  count: number
}

/** Un finding, feuille de l'arbre. */
export interface FindingNode {
  kind: 'finding'
  finding: CodeFinding
}

export type FindingsNode = SeverityNode | FindingNode

/**
 * Extrait l'identifiant d'un finding depuis un argument de commande.
 *
 * Une même commande est déclenchée de trois façons : par l'ampoule (avec
 * une chaîne), par le menu contextuel de la vue (avec le nœud d'arbre) et
 * par la fenêtre de détail (avec une chaîne). On accepte les deux formes
 * plutôt que de dupliquer les commandes.
 */
export function findingUidOf(argument: unknown): string | undefined {
  if (typeof argument === 'string' && argument.length > 0) {
    return argument
  }

  const node = argument as Partial<FindingNode> | undefined
  if (node && node.kind === 'finding' && node.finding?.finding_uid) {
    return node.finding.finding_uid
  }

  return undefined
}

export class FindingsTreeProvider
  implements vscode.TreeDataProvider<FindingsNode>, vscode.Disposable
{
  private readonly emitter = new vscode.EventEmitter<FindingsNode | undefined>()
  readonly onDidChangeTreeData = this.emitter.event

  private readonly store: FindingsStore
  private readonly unsubscribe: Unsubscribe

  constructor(store: FindingsStore) {
    this.store = store
    this.unsubscribe = store.onChange(() => this.emitter.fire(undefined))
  }

  getTreeItem(node: FindingsNode): vscode.TreeItem {
    return node.kind === 'severity' ? this.severityItem(node) : this.findingItem(node)
  }

  getChildren(node?: FindingsNode): FindingsNode[] {
    if (!node) {
      return this.store.grouped().map((group) => ({
        kind: 'severity' as const,
        severity: group.severity,
        count: group.findings.length,
      }))
    }

    if (node.kind === 'severity') {
      const group = this.store
        .grouped()
        .find((candidate) => candidate.severity === node.severity)
      return (group?.findings ?? []).map((finding) => ({
        kind: 'finding' as const,
        finding,
      }))
    }

    return []
  }

  dispose(): void {
    this.unsubscribe()
    this.emitter.dispose()
  }

  // ---------------- Interne ----------------

  private severityItem(node: SeverityNode): vscode.TreeItem {
    const style = SEVERITY_STYLE[node.severity]

    // Les gravités hautes sont dépliées d'office : ce sont celles qu'on
    // doit voir sans un clic de plus.
    const collapsible =
      node.severity === 'CRITICAL' || node.severity === 'HIGH'
        ? vscode.TreeItemCollapsibleState.Expanded
        : vscode.TreeItemCollapsibleState.Collapsed

    const item = new vscode.TreeItem(node.severity, collapsible)
    item.description = String(node.count)
    item.iconPath = themeIcon(style.icon, style.color)
    item.tooltip = `${style.label} — ${node.count}`
    item.contextValue = 'wazuhSecurity.severityGroup'
    // Identifiant stable : VS Code conserve l'état plié/déplié entre deux
    // rafraîchissements plutôt que de tout redéplier à chaque scan.
    item.id = `severity:${node.severity}`
    return item
  }

  private findingItem(node: FindingNode): vscode.TreeItem {
    const { finding } = node
    // Une gravité inconnue d'une version future du backend est affichée en
    // LOW plutôt que de laisser la ligne sans icône.
    const severity = SEVERITY_ORDER.includes(finding.severity as Severity)
      ? (finding.severity as Severity)
      : 'LOW'
    const style = SEVERITY_STYLE[severity]

    const item = new vscode.TreeItem(
      finding.title || finding.category_label || finding.rule_id,
      vscode.TreeItemCollapsibleState.None
    )
    item.id = `finding:${finding.finding_uid}`
    item.description = shortLocation(finding)
    item.iconPath = themeIcon(style.icon, style.color)
    item.tooltip = this.tooltip(finding)

    // `fix_available` distingue les deux menus contextuels sans dupliquer
    // les commandes : le libellé « Corriger » n'apparaît que là où le
    // backend propose vraiment un correctif.
    item.contextValue = finding.fix_available
      ? 'wazuhSecurity.finding.fixable'
      : 'wazuhSecurity.finding'

    item.command = {
      command: 'wazuhSecurity.openFinding',
      title: FR.view.openFinding,
      arguments: [finding.finding_uid],
    }

    return item
  }

  /**
   * Infobulle du finding.
   *
   * `appendText` échappe le contenu dynamique : rien de ce que renvoie le
   * backend — et donc rien de ce que contient le code de l'utilisateur —
   * n'est interprété comme du Markdown ou du HTML. `isTrusted` reste à
   * `false` : aucune commande ne peut être déclenchée depuis l'infobulle.
   */
  private tooltip(finding: CodeFinding): vscode.MarkdownString {
    const tooltip = new vscode.MarkdownString()
    tooltip.isTrusted = false
    tooltip.supportHtml = false

    tooltip.appendText(finding.title || finding.category_label || finding.rule_id)
    tooltip.appendText('\n\n')
    tooltip.appendText(
      `${finding.severity_label || finding.severity} · ${finding.category_label || finding.category}`
    )
    tooltip.appendText('\n')
    tooltip.appendText(`${FR.detail.score} : ${finding.risk_score}/100`)

    const references = [finding.cwe, finding.owasp].filter(Boolean).join(' · ')
    if (references) {
      tooltip.appendText('\n')
      tooltip.appendText(references)
    }

    tooltip.appendText('\n')
    tooltip.appendText(
      `${finding.file_path}:${finding.location?.line_start ?? 0}`
    )

    if (finding.explanation) {
      tooltip.appendText('\n\n')
      tooltip.appendText(finding.explanation)
    }

    tooltip.appendText('\n\n')
    tooltip.appendText(`${FR.detail.detectedBy} : ${finding.source_label || finding.source}`)

    return tooltip
  }
}

// --------------------------------------------------------------------------
// Enregistrement
// --------------------------------------------------------------------------

export interface SecurityViews extends vscode.Disposable {
  readonly overview: RiskOverviewProvider
  readonly findings: FindingsTreeProvider
  /** Met à jour le compteur affiché dans le bandeau de la vue Findings. */
  refreshBadge(): void
}

/**
 * Crée les deux vues et les branche sur le store.
 *
 * Le badge de la vue « Findings » reprend le total ouvert : le nombre est
 * visible depuis la barre d'activité, sans déplier la vue.
 */
export function registerSecurityViews(
  context: vscode.ExtensionContext,
  store: FindingsStore
): SecurityViews {
  const overview = new RiskOverviewProvider(store)
  const findings = new FindingsTreeProvider(store)

  const overviewView = vscode.window.createTreeView('wazuhSecurity.riskOverview', {
    treeDataProvider: overview,
    showCollapseAll: false,
  })

  const findingsView = vscode.window.createTreeView('wazuhSecurity.findings', {
    treeDataProvider: findings,
    showCollapseAll: true,
  })

  const refreshBadge = (): void => {
    const total = store.overview().total
    findingsView.badge =
      total > 0 ? { value: total, tooltip: FR.view.badge(total) } : undefined
    // Le titre secondaire résume l'état sans occuper de ligne dans l'arbre.
    findingsView.description = total > 0 ? FR.view.findingsCount(total) : undefined
  }

  const unsubscribe = store.onChange(refreshBadge)
  refreshBadge()

  const views: SecurityViews = {
    overview,
    findings,
    refreshBadge,
    dispose(): void {
      unsubscribe()
      overviewView.dispose()
      findingsView.dispose()
      overview.dispose()
      findings.dispose()
    },
  }

  context.subscriptions.push(views)
  return views
}
