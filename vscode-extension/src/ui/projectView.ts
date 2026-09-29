/**
 * Vue « Project » : ce que l'agent sait du projet ouvert.
 *
 * Une `TreeView` native de plus dans le conteneur existant — pas de
 * webview, pas de framework, pas de dépendance ajoutée. Même architecture
 * que `securityView.ts`, dont elle reprend les conventions.
 *
 *     SECURITY
 *     ├── Project          ← cette vue
 *     ├── Risk Overview
 *     └── Findings
 *
 * Forme visée, volontairement sobre :
 *
 *     Project              MyApplication
 *     Statut               Prêt
 *     Type de projet       Full-stack
 *     Languages            Python, TypeScript
 *       Python             120 fichiers · 55 %
 *       TypeScript         98 fichiers · 45 %
 *     Frameworks           FastAPI, React
 *       FastAPI            dépendance « fastapi » déclarée — requirements.txt
 *     Files                428 indexés
 *     Fichiers sensibles   3
 *       .env               peut contenir des identifiants
 *     Dépôt Git            ✓ Détecté
 *     Dernière découverte  22:03
 *
 * Trois règles tenues ici
 * -----------------------
 *
 * - **aucun score de sécurité.** La posture explicable, avec sa couverture,
 *   appartient à une phase ultérieure. Un chiffre affiché sans son
 *   explication serait pris pour un verdict.
 * - **une couverture partielle se voit.** Un index tronqué est annoncé dans
 *   la ligne « Files » *et* dans les avertissements.
 * - **aucun contenu de fichier.** Un fichier sensible est listé par son
 *   chemin et la raison de son classement. Rien de plus n'est disponible :
 *   le contrat ne transporte rien d'autre.
 *
 * Les libellés passent par `TreeItem`, que VS Code affiche en texte brut :
 * rien de ce que contient le projet de l'utilisateur n'est interprété.
 */

import * as path from 'node:path'
import * as vscode from 'vscode'

import { FR } from '../i18n/fr'
import type { ProjectContextService } from '../project/projectContext'
import type {
  ClassifiedFile,
  DetectedFramework,
  DetectedLanguage,
  LocalProjectView,
  ProjectStatus,
} from '../project/projectTypes'
import type {
  ApiStatistics,
  DependencyStatistics,
  EcosystemSummary,
  SecretStatistics,
  VulnerabilityStatistics,
} from '../security/securityTypes'
import type { GitSecuritySummary } from '../git/changeAttribution'
import { postureGroups, type PostureInputs } from '../posture/postureView'

// --------------------------------------------------------------------------
// Nœuds
// --------------------------------------------------------------------------

/** Ligne simple : un libellé, une valeur, pas d'enfants. */
interface ValueNode {
  kind: 'value'
  id: string
  label: string
  value: string
  icon: string
  /** Couleur de thème, ou `undefined` pour la couleur par défaut. */
  color?: string | undefined
  tooltip?: string | undefined
}

/** Ligne dépliable : un résumé, et le détail en enfants. */
interface GroupNode {
  kind: 'group'
  id: string
  label: string
  value: string
  icon: string
  color?: string | undefined
  tooltip?: string | undefined
  children: ValueNode[]
  expanded: boolean
}

type ProjectNode = ValueNode | GroupNode

/**
 * Habillage par état.
 *
 * Aucun état n'est vert « tout va bien » : `ready` signifie « la découverte
 * a abouti », pas « ce projet est sûr ». Confondre les deux serait
 * exactement l'affirmation sans preuve que le projet s'interdit.
 */
const STATUS_STYLE: Readonly<Record<ProjectStatus, { icon: string; color: string }>> = {
  discovery: { icon: 'sync~spin', color: 'charts.blue' },
  security_scan: { icon: 'sync~spin', color: 'charts.blue' },
  analysis: { icon: 'sparkle', color: 'charts.purple' },
  ready: { icon: 'pass', color: 'charts.foreground' },
  error: { icon: 'error', color: 'charts.red' },
}

function value(node: Omit<ValueNode, 'kind'>): ValueNode {
  return { kind: 'value', ...node }
}

/** `HH:MM`, heure locale. La date complète est dans l'infobulle. */
function clock(date: Date | undefined): string {
  if (!date) {
    return FR.project.none
  }
  return date.toTimeString().slice(0, 5)
}

function joinOr(items: readonly string[], fallback: string): string {
  return items.length > 0 ? items.join(', ') : fallback
}

// --------------------------------------------------------------------------
// Fournisseur
// --------------------------------------------------------------------------

export class ProjectViewProvider
  implements vscode.TreeDataProvider<ProjectNode>, vscode.Disposable
{
  private readonly emitter = new vscode.EventEmitter<void>()
  readonly onDidChangeTreeData = this.emitter.event

  private readonly service: ProjectContextService
  private readonly unsubscribe: () => void
  /**
   * Bilan des changements Git (phase 4).
   *
   * Injecté plutôt qu'importé : la vue reste affichable sans le service
   * Git, et le module Git n'a pas à connaître l'arbre. Absent = aucune
   * ligne Git, exactement comme avant la phase 4.
   */
  private readonly gitSummary: (() => GitSecuritySummary | undefined) | undefined
  /**
   * Posture de sécurité (phase 8). Injectée comme le bilan Git : la vue ne
   * lit rien elle-même, et absente = aucune section, comme avant.
   */
  private readonly posture: (() => PostureInputs | undefined) | undefined

  constructor(
    service: ProjectContextService,
    gitSummary?: () => GitSecuritySummary | undefined,
    posture?: () => PostureInputs | undefined
  ) {
    this.service = service
    this.gitSummary = gitSummary
    this.posture = posture
    this.unsubscribe = service.onChange(() => this.emitter.fire())
  }

  /** Redessine l'arbre : appelé quand l'analyse Git a produit du neuf. */
  refresh(): void {
    this.emitter.fire()
  }

  getTreeItem(node: ProjectNode): vscode.TreeItem {
    const collapsible =
      node.kind === 'group'
        ? node.expanded
          ? vscode.TreeItemCollapsibleState.Expanded
          : vscode.TreeItemCollapsibleState.Collapsed
        : vscode.TreeItemCollapsibleState.None

    const item = new vscode.TreeItem(node.label, collapsible)
    item.id = node.id
    item.description = node.value
    item.iconPath = new vscode.ThemeIcon(
      node.icon,
      new vscode.ThemeColor(node.color ?? 'charts.foreground')
    )
    // `tooltip` en chaîne simple : VS Code l'affiche en texte brut, donc
    // aucun chemin ni libellé venant du projet n'est interprété.
    item.tooltip = node.tooltip ?? `${node.label} : ${node.value}`
    item.contextValue = `wazuhSecurity.project.${node.kind}`
    return item
  }

  getChildren(node?: ProjectNode): ProjectNode[] {
    if (!node) {
      return this.rootNodes()
    }
    return node.kind === 'group' ? node.children : []
  }

  dispose(): void {
    this.unsubscribe()
    this.emitter.dispose()
  }

  // ---------------- Construction de l'arbre ----------------

  private rootNodes(): ProjectNode[] {
    const view = this.service.current()
    if (!view) {
      // La vue de bienvenue du manifeste prend le relais quand l'arbre est
      // vide : elle dit quoi faire, ce qu'une ligne « aucun projet » ne
      // ferait pas.
      return []
    }

    const nodes: ProjectNode[] = [
      value({
        id: 'project:name',
        label: FR.project.labelProject,
        value: view.projectName,
        icon: 'folder',
        // L'utilisateur connaît son propre disque : le chemin local est
        // utile ici, et ne quitte jamais la machine.
        tooltip: view.workspacePath,
      }),
      this.statusNode(view),
      ...this.postureNodes(),
    ]

    const context = view.context
    if (!context) {
      return nodes
    }

    nodes.push(
      value({
        id: 'project:types',
        label: FR.project.labelTypes,
        value: joinOr(context.project_types, FR.project.unknown),
        icon: 'symbol-structure',
      }),
      this.languagesNode(context.languages),
      this.frameworksNode(context.frameworks),
      value({
        id: 'project:files',
        label: FR.project.labelFiles,
        value: FR.project.filesDetail(
          context.file_statistics.indexed,
          context.file_statistics.discovered,
          context.file_statistics.truncated
        ),
        icon: 'files',
        // Une couverture partielle est signalée par la couleur autant que
        // par le texte : c'est l'information la plus facile à survoler.
        color: context.file_statistics.truncated ? 'charts.orange' : undefined,
      }),
      this.sensitiveNode(context.security_sensitive_files),
      this.secretsNode(context.secret_statistics),
      this.apiNode(context.api_statistics),
      this.dependenciesNode(
        context.dependency_statistics,
        context.dependency_ecosystems
      ),
      this.vulnerabilitiesNode(
        context.vulnerability_statistics,
        context.dependency_statistics
      ),
      value({
        id: 'project:git',
        label: FR.project.labelGit,
        value: context.git_repository_detected
          ? `✓ ${FR.project.gitDetected}`
          : FR.project.gitAbsent,
        icon: context.git_repository_detected ? 'source-control' : 'circle-outline',
        tooltip: context.git_remote_host
          ? `${FR.project.gitDetected} — ${context.git_remote_host}`
          : undefined,
      }),
      ...this.gitNodes(),
      value({
        id: 'project:discovery',
        label: FR.project.labelLastDiscovery,
        value: clock(view.lastDiscovery),
        icon: 'history',
        tooltip: view.lastDiscovery?.toLocaleString() ?? FR.project.none,
      })
    )

    if (context.warnings.length > 0) {
      nodes.push(this.warningsNode(context.warnings))
    }

    return nodes
  }

  /**
   * Posture de sécurité (phase 8), juste sous l'état du projet.
   *
   * Les groupes viennent de `posture/postureView.ts`, qui ne calcule rien
   * qui ne soit déjà un fait. Cette méthode ne fait que les habiller en
   * nœuds d'arbre.
   */
  private postureNodes(): ProjectNode[] {
    const inputs = this.posture?.()
    if (!inputs) {
      return []
    }
    return postureGroups(inputs).map((group) => ({
      kind: 'group' as const,
      id: group.id,
      label: group.label,
      value: group.value,
      icon: group.icon,
      color: group.color,
      tooltip: group.tooltip,
      expanded: group.expanded,
      children: group.children.map((row) => value({ ...row })),
    }))
  }

  /**
   * Bilan des changements Git (phase 4).
   *
   * Vide quand aucun dépôt n'est ouvert ou qu'aucune analyse n'a eu
   * lieu : une section « Changements Git » affichant des zéros se
   * lirait « rien à signaler », alors qu'elle veut dire « rien regardé ».
   *
   * Ce que la section n'affiche **jamais** : l'URL du remote. L'hôte
   * seul, et seulement en infobulle — une URL complète peut porter un
   * jeton d'accès.
   */
  private gitNodes(): ProjectNode[] {
    const summary = this.gitSummary?.()
    if (!summary?.repository) {
      return []
    }

    const children: ValueNode[] = [
      value({
        id: 'git:branch',
        label: FR.git.branchLabel,
        value: summary.branch ?? FR.git.detachedHead,
        icon: 'git-branch',
        tooltip: summary.remoteHost
          ? `${FR.git.remoteLabel} : ${summary.remoteHost}`
          : undefined,
      }),
      value({
        id: 'git:files',
        label: FR.git.changedFilesLabel,
        value: FR.git.changedFilesDetail(
          summary.changedFiles,
          summary.addedLines,
          summary.removedLines
        ),
        icon: 'diff',
        // Une analyse partielle se voit à la couleur autant qu'au texte.
        color: summary.reduced ? 'charts.orange' : undefined,
        tooltip: summary.reduced ? summary.message : undefined,
      }),
      value({
        id: 'git:introduced',
        label: FR.git.introducedLabel,
        value: FR.git.introducedDetail(
          summary.introduced.total,
          summary.conclusive
        ),
        icon: summary.introduced.total > 0 ? 'warning' : 'pass',
        color: !summary.conclusive
          ? 'charts.orange'
          : summary.introduced.critical > 0 || summary.introduced.high > 0
            ? 'charts.red'
            : summary.introduced.total > 0
              ? 'charts.orange'
              : undefined,
        tooltip: summary.conclusive ? undefined : summary.message,
      }),
      value({
        id: 'git:pre-existing',
        label: FR.git.preExistingLabel,
        value: FR.git.preExistingDetail(summary.preExisting.total),
        icon: 'history',
        // Jamais en rouge : ces problèmes sont réels, mais ce changement
        // ne les a pas causés, et les teinter comme s'il en était
        // responsable brouillerait la seule distinction qui compte ici.
        tooltip: FR.git.preExistingLabel,
      }),
    ]

    return [
      {
        kind: 'group',
        id: 'git:section',
        label: FR.git.sectionLabel,
        value: FR.git.introducedDetail(
          summary.introduced.total,
          summary.conclusive
        ),
        icon: 'source-control',
        expanded: summary.introduced.total > 0 || !summary.conclusive,
        children,
      },
    ]
  }

  /**
   * Bilan de sécurité d'API (phase 5).
   *
   * La ligne « Endpoints détectés » dit la **couverture**, pas le risque :
   * un projet sans route reconnue n'est pas un projet sans API, c'est un
   * projet dont l'agent n'a reconnu aucune déclaration. L'infobulle le
   * dit, parce qu'un « 0 » se lirait autrement comme un feu vert.
   */
  private apiNode(statistics: ApiStatistics | undefined): ProjectNode {
    const stats = statistics ?? {
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

    const children: ValueNode[] = [
      value({
        id: 'api:endpoints',
        label: FR.api.labelEndpoints,
        value: FR.api.endpointsDetail(stats.endpoints_detected),
        icon: 'symbol-interface',
        tooltip: FR.api.endpointsTooltip,
      }),
      value({
        id: 'api:unauthenticated',
        label: FR.api.labelUnauthenticated,
        value: FR.api.unauthenticatedDetail(stats.unauthenticated_endpoints),
        icon: stats.unauthenticated_endpoints > 0 ? 'unlock' : 'lock',
        color: stats.unauthenticated_endpoints > 0 ? 'charts.orange' : undefined,
      }),
    ]

    return {
      kind: 'group',
      id: 'api:section',
      label: FR.api.label,
      // « Jamais analysé » et « aucun problème » ne s'écrivent pas pareil.
      value: FR.api.issuesDetail(stats.total, stats.scanned_files),
      icon: 'plug',
      color:
        stats.critical > 0 || stats.high > 0
          ? 'charts.red'
          : stats.total > 0
            ? 'charts.orange'
            : undefined,
      expanded: stats.total > 0,
      children,
    }
  }

  private statusNode(view: LocalProjectView): ValueNode {
    const style = STATUS_STYLE[view.status]
    return value({
      id: 'project:status',
      label: FR.project.labelStatus,
      value: FR.project.status[view.status],
      icon: style.icon,
      color: style.color,
      // En cas d'erreur, l'infobulle porte le message actionnable plutôt
      // qu'un simple « Erreur » qui n'aide personne.
      tooltip: view.error ?? FR.project.status[view.status],
    })
  }

  private languagesNode(languages: readonly DetectedLanguage[]): GroupNode {
    return {
      kind: 'group',
      id: 'project:languages',
      label: FR.project.labelLanguages,
      value: joinOr(
        languages.map((item) => item.language),
        FR.project.none
      ),
      icon: 'code',
      expanded: languages.length > 0 && languages.length <= 4,
      children: languages.map((item) =>
        value({
          id: `project:language:${item.language}`,
          label: item.language,
          value: FR.project.languageDetail(
            item.file_count,
            item.share,
            item.analysis_supported
          ),
          icon: 'symbol-file',
          // Un langage présent sans règles disponibles est signalé : laisser
          // croire à une couverture inexistante tromperait l'utilisateur sur
          // sa propre exposition.
          color: item.analysis_supported ? undefined : 'charts.yellow',
        })
      ),
    }
  }

  private frameworksNode(frameworks: readonly DetectedFramework[]): GroupNode {
    return {
      kind: 'group',
      id: 'project:frameworks',
      label: FR.project.labelFrameworks,
      value: joinOr(
        frameworks.map((item) => item.framework),
        FR.project.none
      ),
      icon: 'layers',
      expanded: false,
      children: frameworks.map((item) =>
        value({
          id: `project:framework:${item.framework}`,
          label: item.framework,
          // La preuve accompagne la détection jusqu'à l'écran : l'utilisateur
          // peut vérifier, et contester.
          value: FR.project.frameworkDetail(item.evidence, item.source),
          icon: 'package',
        })
      ),
    }
  }

  private sensitiveNode(files: readonly ClassifiedFile[]): GroupNode {
    return {
      kind: 'group',
      id: 'project:sensitive',
      label: FR.project.labelSensitive,
      value: String(files.length),
      icon: files.length > 0 ? 'shield' : 'circle-outline',
      color: files.length > 0 ? 'charts.orange' : undefined,
      // Dépliés d'office quand il y en a : c'est l'information la plus
      // actionnable de la vue.
      expanded: files.length > 0 && files.length <= 10,
      children: files.map((file) =>
        value({
          id: `project:sensitive:${file.path}`,
          // Le nom de base suffit à l'identifier ; le chemin complet est
          // dans l'infobulle, comme dans la vue Findings.
          label: path.basename(file.path) || file.path,
          value: FR.project.sensitiveDetail(file.reason),
          icon: 'lock',
          color: 'charts.orange',
          // Le contenu n'est pas affiché parce qu'il n'est pas disponible :
          // ce fichier n'a jamais été lu.
          tooltip: `${file.path}\n${file.type}\n${file.reason}`,
        })
      ),
    }
  }

  /**
   * Ligne « Secrets ».
   *
   * Aucun chemin, aucune preuve : le détail vit dans la vue « Findings »,
   * qui sait le présenter avec sa gravité et sa localisation. Cette ligne
   * répond à une seule question — « ce projet contient-il des secrets
   * exposés ? » — et la couleur y répond avant le texte.
   *
   * `last_scan` absent signifie « jamais analysé », pas « aucun secret ».
   * Les deux s'écrivent différemment, parce qu'ils ne se valent pas.
   */
  private secretsNode(statistics: SecretStatistics): ValueNode {
    const neverScanned = !statistics.last_scan
    const total = statistics.total

    return value({
      id: 'project:secrets',
      label: FR.security.labelSecrets,
      value: neverScanned
        ? FR.security.secretsNeverScanned
        : FR.security.secretsDetail(total, statistics.files_with_secrets),
      icon: total > 0 ? 'key' : 'circle-outline',
      color: total > 0 ? 'charts.red' : undefined,
      tooltip: neverScanned
        ? FR.security.secretsNeverScanned
        : `${statistics.scanned_files} fichier(s) analysé(s)` +
          (statistics.truncated ? ' — balayage tronqué' : '') +
          (statistics.engine ? `\n${statistics.engine}` : ''),
    })
  }

  /**
   * Groupe « Dépendances », déplié par écosystème.
   *
   * Le détail par écosystème montre ce que le total masque : un projet
   * peut avoir toutes ses dépendances npm vérifiées et aucune de ses
   * dépendances Maven, parce que les versions y sont portées par des
   * propriétés non résolues.
   */
  private dependenciesNode(
    statistics: DependencyStatistics,
    ecosystems: readonly EcosystemSummary[]
  ): GroupNode {
    return {
      kind: 'group',
      id: 'project:dependencies',
      label: FR.security.labelDependencies,
      value: FR.security.dependenciesDetail(
        statistics.total,
        statistics.direct,
        statistics.transitive
      ),
      icon: 'package',
      color: statistics.vulnerable > 0 ? 'charts.red' : undefined,
      expanded: false,
      tooltip:
        `${statistics.manifests_read} manifeste(s) lu(s)` +
        (statistics.truncated ? ' — inventaire tronqué' : ''),
      children: ecosystems.map((entry) =>
        value({
          id: `project:ecosystem:${entry.ecosystem}`,
          label: entry.ecosystem,
          value: FR.security.ecosystemDetail(
            entry.total,
            entry.vulnerable,
            entry.verified
          ),
          icon: 'library',
          // Non vérifié n'est pas sain : la couleur le dit avant le texte.
          color:
            entry.vulnerable > 0
              ? 'charts.red'
              : entry.verified < entry.total
                ? 'charts.yellow'
                : undefined,
        })
      ),
    }
  }

  /**
   * Ligne « Vulnérabilités ».
   *
   * Le point le plus important de cette vue, et celui où il serait le plus
   * facile de mentir. Quand le fournisseur n'a pas conclu, la ligne
   * affiche **son état** et non un chiffre : un « 0 » resterait lisible
   * comme un feu vert, même accompagné d'une infobulle que personne
   * n'ouvre.
   *
   * L'icône suit la même règle — jamais de coche verte sans vérification.
   */
  private vulnerabilitiesNode(
    statistics: VulnerabilityStatistics,
    dependencies: DependencyStatistics
  ): ValueNode {
    const conclusive = statistics.conclusive
    const total = statistics.total

    const icon = !conclusive
      ? 'question'
      : total > 0
        ? 'shield'
        : dependencies.unverified > 0
          ? 'info'
          : 'pass'

    const color = !conclusive
      ? 'charts.yellow'
      : total > 0
        ? 'charts.red'
        : dependencies.unverified > 0
          ? 'charts.yellow'
          : undefined

    return value({
      id: 'project:vulnerabilities',
      label: FR.security.labelVulnerabilities,
      value: FR.security.vulnerabilitiesDetail(
        total,
        conclusive,
        statistics.provider_status_label
      ),
      icon,
      color,
      // Le message vient du backend : c'est lui qui rédige une fois pour
      // toutes la phrase qui distingue « vérifié » de « non vérifiable ».
      tooltip:
        `${statistics.message}\n\n` +
        FR.security.providerTooltip(
          statistics.provider || '—',
          statistics.provider_status_label
        ) +
        (dependencies.unverified > 0
          ? `\n${FR.security.unverifiedDetail(dependencies.unverified)}`
          : ''),
    })
  }

  private warningsNode(warnings: readonly string[]): GroupNode {
    return {
      kind: 'group',
      id: 'project:warnings',
      label: FR.project.labelWarnings,
      value: String(warnings.length),
      icon: 'warning',
      color: 'charts.yellow',
      expanded: true,
      children: warnings.map((warning, position) =>
        value({
          id: `project:warning:${position}`,
          label: warning,
          value: '',
          icon: 'info',
          color: 'charts.yellow',
          tooltip: warning,
        })
      ),
    }
  }
}

// --------------------------------------------------------------------------
// Enregistrement
// --------------------------------------------------------------------------

export interface ProjectViewHandle extends vscode.Disposable {
  readonly provider: ProjectViewProvider
}

export function registerProjectView(
  context: vscode.ExtensionContext,
  service: ProjectContextService,
  gitSummary?: () => GitSecuritySummary | undefined,
  posture?: () => PostureInputs | undefined
): ProjectViewHandle {
  const provider = new ProjectViewProvider(service, gitSummary, posture)
  const view = vscode.window.createTreeView('wazuhSecurity.project', {
    treeDataProvider: provider,
    showCollapseAll: false,
  })

  // Le nom du projet dans le bandeau : visible sans déplier, et sans
  // occuper de ligne dans l'arbre.
  const refreshTitle = (): void => {
    const current = service.current()
    view.description = current?.projectName ?? undefined
  }
  const unsubscribe = service.onChange(refreshTitle)
  refreshTitle()

  const handle: ProjectViewHandle = {
    provider,
    dispose(): void {
      unsubscribe()
      view.dispose()
      provider.dispose()
    },
  }

  context.subscriptions.push(handle)
  return handle
}
