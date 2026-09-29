/**
 * Point d'entrée de l'extension Wazuh Security.
 *
 * Chaîne complète :
 *
 *     VS Code  →  extension  →  FastAPI /api/code/*  →  moteur de règles
 *              ←  findings   ←
 *
 * L'extension ne parle **jamais** directement à Wazuh Manager, à
 * l'Indexer ou à OpenAI : le backend reste le seul cerveau de sécurité,
 * et le seul détenteur d'informations d'identification.
 *
 * La vue « Security » (barre d'activité) affiche exactement les findings
 * produits par ces mêmes routes : un seul store, une seule source.
 *
 * Phase 0 — authentification et adresse du backend
 * ------------------------------------------------
 *
 * Chaque appel porte `Authorization: Bearer <jeton local>`. Le jeton est lu
 * dans le fichier que le backend écrit à son démarrage, puis conservé dans
 * `SecretStorage` — jamais dans un réglage, jamais dans le code.
 *
 * L'adresse du backend est **validée** avant usage : elle décide où part le
 * contenu des fichiers analysés, et un dépôt cloné ne doit pas pouvoir la
 * détourner. Voir `api/backendUrl.ts`.
 *
 * Phase 1 — contexte de projet
 * ----------------------------
 *
 * À l'ouverture d'un dossier, l'agent établit ce qu'il sait du projet :
 * langages, frameworks, type, fichiers importants et sensibles. En
 * arrière-plan, annulable, sans bloquer l'interface. La découverte n'indexe
 * que des métadonnées et ne déclenche **aucune** analyse de sécurité.
 */

import * as vscode from 'vscode'

import { AgentToken } from './api/agentToken'
import { BackendClient, BackendError, type CodeFinding } from './api/backendClient'
import {
  DEFAULT_BACKEND_URL,
  shouldAdvertiseBackend,
  validateBackendUrl,
  type BackendUrlVerdict,
} from './api/backendUrl'
import { StreamClient } from './api/streamClient'
import { ScanController, workspaceRoot } from './analysis/scanController'
import { syncHistory } from './analysis/historySync'
import { scanWorkspace } from './analysis/workspaceScan'
import { DiagnosticsProvider } from './diagnostics/provider'
import { ProjectDiagnostics } from './diagnostics/projectDiagnostics'
import { FindingsStore } from './state/findingsStore'
import { FindingDetailPanel } from './ui/detailPanel'
import { NotificationCenter } from './ui/notifications'
import {
  SecurityCodeActionProvider,
  applyFix,
  dismissFinding,
  type ActionContext,
} from './ui/quickFix'
import { openInEditor, revealFinding } from './ui/revealFinding'
import { findingUidOf, registerSecurityViews } from './ui/securityView'
import { StatusBar } from './ui/statusBar'
import { GitignoreMatcher, SUPPORTED_LANGUAGES } from './analysis/documentFilter'
import { pickScanTarget } from './analysis/activeDocument'
import { ProjectContextService } from './project/projectContext'
import { runStartup } from './project/startup'
import type { GitMetadata } from './project/projectTypes'
import { ProjectSecurityService } from './security/projectSecurityService'
import { isProjectFinding, toViewFindings } from './security/findingAdapter'
import type { SecurityAiHealth } from './ai/aiTypes'
import { SecurityAiPanel } from './ui/aiPanel'
import { AiFixWorkflow } from './remediation/fixWorkflow'
import type { PostureInputs } from './posture/postureView'
import {
  normalizeCiMode,
  type CiCheckResult,
  type SecurityPosture,
} from './posture/postureTypes'
import type { SecurityFinding } from './security/securityTypes'
import { registerProjectView } from './ui/projectView'
import { ProjectMonitor } from './monitor/projectMonitor'
import { DEFAULT_DEBOUNCE_MS } from './monitor/scanQueue'
import {
  DEFAULT_BUDGET_MS,
  DEFAULT_MAX_CHANGED_FILES,
  GitSecurityService,
} from './git/gitSecurityService'
import { GitMonitor } from './git/gitMonitor'
import { VsCodeGitWorkspace } from './git/vscodeGitWorkspace'
import { runPrePushCheck } from './git/prePushCheck'
import { normalizeMode, type PrePushMode } from './git/prePushPolicy'
import { remoteHostOf } from './git/remoteUrl'
import type { AttributedFinding } from './git/changeAttribution'
import { FR } from './i18n/fr'

let output: vscode.OutputChannel
let client: BackendClient
let controller: ScanController
let store: FindingsStore
let diagnostics: DiagnosticsProvider
let statusBar: StatusBar
let notifications: NotificationCenter
let stream: StreamClient | undefined
let token: AgentToken
let project: ProjectContextService
let security: ProjectSecurityService
let projectDiagnostics: ProjectDiagnostics
/**
 * Surveillance continue (phase 3).
 *
 * Construite a l'activation, demarree seulement quand un dossier est
 * ouvert et que le reglage l'autorise. Elle ne fabrique aucun finding :
 * elle alimente les moteurs des phases 1 et 2, et republie ce que le
 * backend renvoie.
 */
let monitor: ProjectMonitor
/**
 * Securite des changements Git (phase 4).
 *
 * Classe les findings existants en « introduit par ce changement » et
 * « preexistant ». Ne cree aucun finding et n'ajoute aucune route.
 */
let gitSecurity: GitSecurityService
let gitMonitor: GitMonitor
/**
 * Remédiation assistée (phase 7). Propose, montre, fait confirmer,
 * applique, puis laisse les moteurs déterministes juger.
 */
let aiFix: AiFixWorkflow
/**
 * Posture de sécurité (phase 8), telle que le backend l'a lue en dernier.
 * Aucune valeur n'est calculée ici : c'est une copie d'affichage.
 */
let postureState: { posture?: SecurityPosture; ci?: CiCheckResult; error?: string } = {}
let postureTimer: ReturnType<typeof setTimeout> | undefined
let projectView: { provider: { refresh(): void } } | undefined
/**
 * Le backend porte-t-il le moteur de sécurité projet ?
 *
 * Annoncé par `/api/code/health`. Faux tant qu'on ne l'a pas vérifié :
 * mieux vaut ne pas balayer que parcourir tout le disque pour se faire
 * répondre 404.
 */
let projectSecurityEnabled = false
/**
 * Une action IA est-elle disponible ? Pilote la visibilité de « Analyze
 * with AI » : vrai si l'enrichissement du code **ou** l'assistant de
 * sécurité (phase 6) est annoncé par le backend.
 */
let aiEnabled = false
/** Enrichissement IA du code, annoncé par /api/code/health. */
let codeAiEnabled = false
/**
 * État de l'assistant IA de sécurité (phase 6), tel que le backend l'a
 * annoncé. `undefined` = inconnu ou backend plus ancien : lu comme
 * « absent ». La détection ne dépend jamais de cette valeur.
 */
let securityAiHealth: SecurityAiHealth | undefined
/** Découverte en cours : sert à l'annuler proprement à la désactivation. */
let discoveryCancellation: vscode.CancellationTokenSource | undefined

export function activate(context: vscode.ExtensionContext): void {
  output = vscode.window.createOutputChannel(FR.outputChannel)
  context.subscriptions.push(output)

  // Le jeton est résolu paresseusement : l'activation ne doit pas attendre
  // une lecture disque, et le backend n'a peut-être pas encore démarré.
  token = new AgentToken({
    vault: context.secrets,
    onLog: (message) => log(message),
  })

  // L'adresse est validée avant le premier appel : elle décide où part le
  // contenu des fichiers analysés.
  const initial = resolveBackendUrl()

  // `onTrace` ne journalise que la forme des échanges — méthode, URL,
  // code HTTP, durée. Jamais un corps de requête ni de réponse : le code
  // de l'utilisateur ne doit apparaître dans aucun journal. Le jeton non
  // plus : il est ajouté par `authHeader`, qui ne passe pas par la trace.
  client = new BackendClient({
    // Repli sur la boucle locale si l'adresse est refusee : c'est l'option
    // la plus restrictive, et `announceBackend` l'annonce a l'utilisateur.
    baseUrl: initial.ok ? initial.url : DEFAULT_BACKEND_URL,
    onTrace: (message) => debug(message),
    authHeader: () => token.authorizationHeader(),
    // Le backend a pu redémarrer avec un nouveau jeton : on relit le
    // fichier une fois plutôt que de rester muet jusqu'au redémarrage de
    // l'éditeur.
    onUnauthorized: async () => {
      const { token: refreshed } = await token.refresh()
      return refreshed !== undefined
    },
  })

  diagnostics = new DiagnosticsProvider()
  statusBar = new StatusBar()
  store = new FindingsStore()
  notifications = new NotificationCenter({
    isAiEnabled: () => aiEnabled,
    log,
  })
  // La détection tourne dans l'extension, la persistance et la base de
  // vulnérabilités dans le backend. Le service est injecté dans le
  // contexte de projet plutôt qu'appelé depuis lui : le parcours reste
  // testable sans backend de sécurité.
  security = new ProjectSecurityService({ client, log })
  project = new ProjectContextService({ client, log, security })
  projectDiagnostics = new ProjectDiagnostics(() => workspaceRoot())

  controller = new ScanController({
    client,
    diagnostics,
    statusBar,
    output,
    store,
    notifications,
    // Résolu à chaque analyse, pas capturé : l'identifiant apparaît après
    // la première découverte et change quand on ouvre un autre dossier.
    projectUid: () => project.projectUid(),
  })

  // Securite des changements Git (phase 4). Construite ici, demarree plus
  // bas : elle a besoin d'un dossier ouvert, et l'extension Git de VS Code
  // peut ne pas etre encore active.
  //
  // Elle lit les findings **du registre existant** : aucune seconde
  // source, aucune seconde table.
  gitSecurity = new GitSecurityService({
    // Seule piece de la phase 4 qui parle a l'editeur. Tout ce qui
    // decide vit dans des modules purs, testables sans VS Code.
    workspace: new VsCodeGitWorkspace({ workspaceRoot }),
    knownFindings: () => projectSecurityFindings,
    ignore: () => gitignoreMatcher(workspaceRoot()),
    maxChangedFiles: gitMaxChangedFiles,
    log,
  })

  gitMonitor = new GitMonitor({
    workspaceRoot,
    isEnabled: gitEnabled,
    // Un changement de branche recalcule l'attribution, et **rien
    // d'autre** : aucun parcours complet du projet n'est relance.
    onChanged: () => {
      void refreshGitAnalysis()
    },
    log,
  })

  // Surveillance continue (phase 3). Construite ici, demarree plus bas :
  // elle a besoin d'un dossier ouvert, et l'etat du backend n'est pas
  // encore connu a cet instant.
  monitor = new ProjectMonitor({
    controller,
    security,
    statusBar,
    projectUid: () => project.projectUid(),
    workspaceRoot,
    ignore: () => gitignoreMatcher(workspaceRoot()),
    isEnabled: monitoringEnabled,
    // Les analyses de la surveillance obeissent aux memes reglages que
    // le reste : elle n'est pas une porte derobee pour faire tourner ce
    // que l'utilisateur a desactive.
    wantsCode: () => autoScanEnabled(),
    wantsSecrets: secretDetectionEnabled,
    wantsApi: apiSecurityEnabled,
    wantsDependencies: dependencyAnalysisEnabled,
    checkVulnerabilities: vulnerabilityCheckEnabled,
    debounceMs: monitoringDebounceMs,
    projectSecurityEnabled: () => projectSecurityEnabled,
    // Le meme chemin que la decouverte complete : un seul registre, une
    // seule vue, une seule regle de deduplication des bulles.
    onSecurityFindings: (findings) => applySecurityFindings(findings),
    log,
  })

  // Remédiation assistée (phase 7). Aucun moteur nouveau : la nouvelle
  // analyse passe par la surveillance (sécurité projet) ou par le
  // contrôleur (analyse de code), exactement comme un changement ordinaire.
  aiFix = new AiFixWorkflow({
    client,
    store,
    projectUid: () => project.projectUid(),
    openAssistant: () => openSecurityAssistant(),
    rescanProjectFile: (relative) => monitor.rescanFile(relative),
    fullSecurityScan: () => discoverProjectContext({ notify: false, forceSecurity: true }),
    rescanCodeDocument: (document) => controller.scanNow(document),
    log,
  })

  context.subscriptions.push(
    diagnostics,
    statusBar,
    notifications,
    controller,
    projectDiagnostics,
    monitor,
    gitMonitor,
    aiFix
  )

  // Vue « Security » : Project + Risk Overview + Findings. La vue Project
  // lit le service de contexte, les deux autres le store : chacune a une
  // source unique, et elles se redessinent sur son événement.
  registerSecurityViews(context, store)
  projectView = registerProjectView(
    context,
    project,
    () => gitSecurity.summary(),
    () => postureInputs()
  )

  // Posture (phase 8) : relue quand les findings ou le contexte changent.
  // Anti-rebond : une rafale d'analyses ne produit qu'une lecture.
  const unsubscribePosture = store.onChange(() => schedulePostureRefresh())
  const unsubscribeProjectPosture = project.onChange(() => schedulePostureRefresh())
  context.subscriptions.push({
    dispose: () => {
      unsubscribePosture()
      unsubscribeProjectPosture()
      if (postureTimer) {
        clearTimeout(postureTimer)
      }
    },
  })

  // Les deux arbres se rafraîchissent sur cet événement : le tracer ici
  // prouve que la vue a bien été notifiée, et avec quels compteurs.
  context.subscriptions.push({
    dispose: store.onChange(() => {
      const overview = store.overview()
      debug(
        `vues Findings et Risk Overview rafraîchies — ${overview.total} finding(s) ` +
          `[${overview.critical}C ${overview.high}H ${overview.medium}M ${overview.low}L] ` +
          `sur ${store.files().length} fichier(s)`
      )
    }),
  })

  const actions: ActionContext = {
    client,
    diagnostics,
    statusBar,
    store,
    // Après une correction, l'analyse est relancée par le contrôleur
    // existant : diagnostics, barre d'état, vue Security et empreinte de
    // référence sont rafraîchis d'un seul coup.
    rescan: (document) => controller.scanNow(document),
    log,
  }

  // Actions rapides (ampoule) sur les langages analysés.
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      Object.keys(SUPPORTED_LANGUAGES).map((language) => ({ language })),
      new SecurityCodeActionProvider(diagnostics),
      SecurityCodeActionProvider.metadata
    )
  )

  log(`extension activée — backend ${client.url}`)
  announceBackend(initial)
  reportWorkspace()

  // --- Commandes -------------------------------------------------------

  context.subscriptions.push(
    vscode.commands.registerCommand('wazuhSecurity.scanCurrentFile', async () => {
      debug('scanCurrentFile() START')
      const active = vscode.window.activeTextEditor?.document
      debug(
        `  éditeur actif : ${
          active
            ? `${active.uri.toString()} (langage « ${active.languageId} »)`
            : '(aucun)'
        }`
      )

      const document = activeSourceDocument()
      if (!document) {
        debug('scanCurrentFile() END — aucun document source à analyser')
        void vscode.window.showInformationMessage(FR.scanNoDocument)
        return
      }

      debug(
        `  document retenu : ${document.fileName} · langage « ${document.languageId} »`
      )
      // Le langage retenu est tracé : c'est lui qui décide de l'analyse,
      // et c'est la première chose à vérifier quand un fichier est refusé.
      log(`scan demandé — ${document.uri.fsPath} (langage « ${document.languageId} »)`)

      // Aucune erreur ne doit rester dans l'ombre : `scanNow` traite ses
      // pannes, mais un imprévu ne doit pas se solder par une commande
      // silencieuse.
      try {
        await controller.scanNow(document)
      } catch (error) {
        const detail = error instanceof Error ? error.message : String(error)
        debug(`  erreur inattendue : ${detail}`)
        void vscode.window.showErrorMessage(FR.scanFailed(FR.errors.unexpected))
      }
      debug('scanCurrentFile() END')
    })
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('wazuhSecurity.scanWorkspace', async () => {
      await scanWorkspace(controller, log)
    })
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('wazuhSecurity.clearFindings', () => {
      controller.clearAll()
      // La vue est videe dans son entier : les findings de securite
      // projet aussi, sinon la commande mentirait sur son effet.
      projectDiagnostics.clear()
      security.clear()
      // Le classement Git portait sur ces findings : il ne decrit plus
      // rien une fois la vue videe.
      projectSecurityFindings = []
      gitSecurity.clear()
      projectView?.provider.refresh()
      void vscode.window.showInformationMessage(FR.view.cleared)
    })
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('wazuhSecurity.refreshFindings', async () => {
      await refreshFindings(true)
    })
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('wazuhSecurity.checkBackend', async () => {
      await checkBackend({ notifyOnSuccess: true, syncHistory: false })
    })
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('wazuhSecurity.refreshProject', async () => {
      await discoverProjectContext({ notify: true })
    })
  )

  // « Scan Project Security » : meme parcours, avec les analyses de la
  // phase 2 explicitement demandees. Une commande distincte plutot qu'un
  // reglage seul, pour que l'utilisateur puisse relancer un balayage sans
  // attendre la prochaine ouverture du dossier.
  context.subscriptions.push(
    vscode.commands.registerCommand('wazuhSecurity.scanProjectSecurity', async () => {
      await discoverProjectContext({ notify: true, forceSecurity: true })
    })
  )

  // --- Changements Git (phase 4) ----------------------------------------

  context.subscriptions.push(
    vscode.commands.registerCommand('wazuhSecurity.scanGitChanges', async () => {
      if (!gitEnabled()) {
        void vscode.window.showInformationMessage(FR.git.disabled)
        return
      }
      if (!workspaceRoot()) {
        void vscode.window.showInformationMessage(FR.git.noWorkspace)
        return
      }

      await refreshGitAnalysis()
      const summary = gitSecurity.summary()

      if (!summary.repository) {
        void vscode.window.showInformationMessage(FR.git.noRepository)
        return
      }
      if (!summary.conclusive) {
        // Non concluant : on affiche la raison, jamais un zero rassurant.
        void vscode.window.showWarningMessage(summary.message || FR.git.timedOut)
        return
      }

      void vscode.window.showInformationMessage(
        FR.git.analysisDone(
          summary.branch ?? FR.git.detachedHead,
          summary.changedFiles,
          summary.introduced.total,
          summary.preExisting.total
        ) + (summary.reduced ? ` ${summary.message}` : '')
      )
    })
  )

  // « Check Changes Before Push » : la verification est lancee **par
  // l'utilisateur**. L'extension n'installe aucun hook Git — voir
  // `git/prePushCheck.ts` pour le raisonnement.
  context.subscriptions.push(
    vscode.commands.registerCommand('wazuhSecurity.checkBeforePush', async () => {
      if (!workspaceRoot()) {
        void vscode.window.showInformationMessage(FR.git.noWorkspace)
        return
      }

      await runPrePushCheck({
        service: gitSecurity,
        mode: prePushMode,
        budgetMs: gitBudgetMs,
        log,
        reveal: revealAttributed,
      })
      projectView?.provider.refresh()
    })
  )

  // --- Actions sur un finding ------------------------------------------
  //
  // Ces commandes acceptent soit un identifiant (ampoule, fenêtre de
  // détail), soit le nœud de l'arbre (menu contextuel de la vue) :
  // `findingUidOf` réconcilie les deux, plutôt que de dupliquer les
  // commandes par point d'appel.

  context.subscriptions.push(
    vscode.commands.registerCommand('wazuhSecurity.applyFix', async (argument: unknown) => {
      const uid = findingUidOf(argument)
      if (uid) {
        await applyFix(actions, uid)
      }
    })
  )

  context.subscriptions.push(
    vscode.commands.registerCommand(
      'wazuhSecurity.dismissFinding',
      async (argument: unknown) => {
        const uid = findingUidOf(argument)
        if (uid) {
          await dismissFinding(actions, uid)
        }
      }
    )
  )

  // « View Issue » : la fiche seule, sans déplacer le curseur.
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'wazuhSecurity.showFindingDetail',
      (argument: unknown) => {
        const uid = findingUidOf(argument)
        if (!uid) {
          return
        }

        // Les diagnostics du document ouvert d'abord, la vue ensuite : les
        // deux registres portent le même finding, jamais deux copies
        // divergentes.
        const finding = diagnostics.findByUid(uid)?.finding ?? store.get(uid)
        if (!finding) {
          void vscode.window.showWarningMessage(FR.actions.findingUnknown)
          return
        }

        FindingDetailPanel.show(finding, {
          aiAvailable: aiAvailableFor(finding),
          aiFixAvailable: securityFixAvailable(),
        })
      }
    )
  )

  // Clic sur un finding dans la vue : fichier ouvert, curseur placé, fiche
  // affichée.
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'wazuhSecurity.openFinding',
      async (argument: unknown) => {
        const uid = findingUidOf(argument)
        if (uid) {
          await revealFinding(store, uid, log, aiAvailableFor, securityFixAvailable)
        }
      }
    )
  )

  // « Analyze with AI » : le même scan, avec l'enrichissement demandé au
  // backend. L'extension n'appelle aucun modèle elle-même.
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'wazuhSecurity.analyzeWithAi',
      async (argument: unknown) => {
        await analyzeWithAi(argument)
      }
    )
  )

  // --- Assistant IA de sécurité (phase 6) ------------------------------
  //
  // Deux commandes de plus, et aucune seconde vue de findings : l'assistant
  // lit ce que les moteurs ont déjà produit, par l'intermédiaire du
  // backend. Aucune de ces commandes ne crée, ne retire ni ne requalifie
  // un finding.

  context.subscriptions.push(
    vscode.commands.registerCommand('wazuhSecurity.securityChat', async () => {
      const assistant = await openSecurityAssistant()
      assistant?.showChat()
    })
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('wazuhSecurity.summarizeWithAi', async () => {
      const assistant = await openSecurityAssistant()
      await assistant?.summarize()
    })
  )

  // --- Remédiation assistée (phase 7) ----------------------------------
  //
  // « Suggest Fix with AI » ne modifie rien : il montre une proposition.
  // « Appliquer » passe par une confirmation modale, puis par les moteurs
  // déterministes. Aucune de ces commandes n'enregistre de décision sur
  // le finding.

  context.subscriptions.push(
    vscode.commands.registerCommand(
      'wazuhSecurity.suggestFixWithAi',
      async (argument: unknown) => {
        const uid = findingUidOf(argument)
        if (uid) {
          await aiFix.suggest(uid)
        }
      }
    ),
    vscode.commands.registerCommand('wazuhSecurity.applyAiFix', () => aiFix.apply()),
    vscode.commands.registerCommand('wazuhSecurity.cancelAiFix', () => aiFix.cancel()),
    vscode.commands.registerCommand('wazuhSecurity.showAiFixDiff', () => aiFix.showDiff())
  )

  // --- Analyse à la sauvegarde -----------------------------------------

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) => {
      if (!autoScanEnabled() || !scanOnSaveEnabled()) {
        return
      }
      // Programmé, pas exécuté : l'anti-rebond regroupe les sauvegardes
      // rapprochées et le fil de l'interface n'attend rien.
      controller.scheduleScan(document)
    })
  )

  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((document) => {
      // Les diagnostics disparaissent avec le document ; la vue, elle,
      // conserve les findings du fichier refermé.
      controller.forget(document)
    })
  )

  // --- Réactions aux changements d'environnement ------------------------

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      const addressChanged =
        event.affectsConfiguration('wazuhSecurity.backendUrl') ||
        event.affectsConfiguration('wazuhSecurity.allowRemoteBackend')

      if (event.affectsConfiguration('wazuhSecurity.ci')) {
        schedulePostureRefresh()
      }

      if (event.affectsConfiguration('wazuhSecurity.git')) {
        syncGitMonitoring()
        // Le rappel « aucun hook installe » n'est donne qu'au passage en
        // « block » : c'est la seule situation ou l'on pourrait croire
        // etre protege partout.
        if (prePushMode() === 'block') {
          void vscode.window.showInformationMessage(FR.git.noHookInstalled)
        }
      }

      if (event.affectsConfiguration('wazuhSecurity.monitoring')) {
        // Le reglage est relu, pas seulement au demarrage : activer la
        // surveillance ne doit pas demander de redemarrer l'editeur.
        syncMonitoring()
      }

      if (addressChanged) {
        // Revalidée, pas seulement relue : un réglage peut devenir
        // inacceptable sans que l'extension redémarre.
        const verdict = resolveBackendUrl()
        client.setBaseUrl(verdict.ok ? verdict.url : DEFAULT_BACKEND_URL)
        log(`adresse du backend mise à jour : ${client.url}`)
        announceBackend(verdict)
        restartStream()
        // Nouveau backend : son historique remplace celui qu'on affichait.
        void checkBackend({ notifyOnSuccess: false, syncHistory: true })
      }
    })
  )

  context.subscriptions.push(
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      controller.reloadGitignore()
      reportWorkspace()
      // Autre dossier, autre projet : le contexte précédent ne décrit plus
      // rien. On l'oublie avant de redécouvrir, pour ne jamais afficher le
      // contexte d'un projet sous le nom d'un autre.
      project.clear()
      security.clear()
      projectDiagnostics.clear()
      // Autre dossier, autre projet : le registre et le cache
      // d'empreintes de la surveillance decrivent le precedent. Les
      // conserver ferait soumettre ses constats sous l'identifiant du
      // suivant.
      monitor.stop()
      monitor.reset()
      // Autre dossier, autre depot : l'analyse Git precedente ne decrit
      // plus rien.
      gitMonitor.stop()
      gitSecurity.clear()
      projectSecurityFindings = []
      syncGitMonitoring()
      restartStream()
      void discoverProjectContext({ notify: false })
    })
  )

  // --- Backend, contexte de projet, historique : dans cet ordre ---------
  //
  // Sans bloquer l'activation : `void` volontaire, l'extension est
  // utilisable avant même que le backend ait répondu. L'ordre, lui, est
  // imposé — voir `project/startup.ts`.
  void runStartup({
    folderOpen: workspaceRoot() !== undefined,
    discoverOnStartup: discoverOnStartupEnabled(),
    syncOnStartup: syncOnStartupEnabled(),
    checkBackend: (syncHistory) => checkBackend({ notifyOnSuccess: false, syncHistory }),
    discover: () => discoverProjectContext({ notify: false }),
    projectUid: () => project.projectUid(),
    syncHistory: () => refreshFindings(false),
  })

  // --- Surveillance continue : demarree si un dossier est ouvert -------
  //
  // Demarree meme sans registre de reference : l'analyse de code n'en a
  // pas besoin, et la barre d'etat doit annoncer l'etat reel. La partie
  // securite projet attend la premiere decouverte, et le journal le dit.
  syncMonitoring()

  // --- Changements Git : demarres si un depot est ouvert ---------------
  //
  // `void` volontaire : l'extension Git de VS Code peut mettre un moment
  // a s'activer, et l'editeur reste utilisable pendant ce temps.
  syncGitMonitoring()

  // --- Flux temps réel : la vue reste correcte sans lui ----------------
  startStream()
}

/**
 * Aligne la surveillance sur le reglage et sur le dossier ouvert.
 *
 * Un seul chemin pour les trois declencheurs — activation, changement de
 * reglage, fin de decouverte — plutot qu'une condition recopiee trois
 * fois, qui finirait par diverger.
 */
function syncMonitoring(): void {
  if (!monitor) {
    return
  }

  if (monitoringEnabled() && workspaceRoot()) {
    monitor.start()
    return
  }

  monitor.stop()
}

/**
 * Fermeture de l'extension : rien ne doit survivre.
 *
 * VS Code libère `context.subscriptions` de son côté, mais l'ordre n'est
 * pas garanti et les minuteurs sont ce qui reste le plus volontiers en
 * arrière-plan. On les arrête donc explicitement, dans l'ordre : le flux
 * d'abord — pour qu'aucune reconnexion ne soit programmée pendant qu'on
 * démonte le reste —, puis les analyses et relectures en attente, puis
 * les bulles différées, enfin la fenêtre de détail.
 *
 * Toutes ces méthodes sont sans effet si elles sont rappelées.
 */
export function deactivate(): void {
  stream?.dispose()
  stream = undefined

  // Un parcours de projet en vol continuerait à lire le disque après la
  // désactivation : il est annulé avant tout le reste.
  discoveryCancellation?.cancel()
  discoveryCancellation?.dispose()
  discoveryCancellation = undefined

  // La surveillance tient un watcher et des minuteurs : elle est
  // arretee avant le reste, pour qu'aucun evenement n'arrive pendant le
  // demontage.
  monitor?.dispose()
  gitMonitor?.dispose()

  controller?.dispose()
  notifications?.dispose()
  projectDiagnostics?.dispose()

  FindingDetailPanel.disposeCurrent()
  SecurityAiPanel.disposeCurrent()
  aiFix?.dispose()
}

// --------------------------------------------------------------------------
// Réglages
// --------------------------------------------------------------------------

function configuration(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration('wazuhSecurity')
}

function configuredBackendUrl(): string {
  return configuration().get<string>('backendUrl', DEFAULT_BACKEND_URL)
}

function allowRemoteBackendEnabled(): boolean {
  return configuration().get<boolean>('allowRemoteBackend', false)
}

function discoverOnStartupEnabled(): boolean {
  return configuration().get<boolean>('project.discoverOnStartup', true)
}

/**
 * Assistant IA de sécurité (phase 6), côté utilisateur.
 *
 * Désactivé, l'extension n'appelle aucune route IA et n'affiche aucun
 * bouton d'assistant — même si le backend l'annonce. La détection n'en
 * dépend pas.
 */
function aiAssistantSettingEnabled(): boolean {
  return configuration().get<boolean>('ai.assistant', true)
}

/** Détection de secrets pendant la découverte. Locale, sans appel réseau. */
function secretDetectionEnabled(): boolean {
  return configuration().get<boolean>('project.secretDetection', true)
}

/** Inventaire des dépendances. Lecture de manifestes, aucune installation. */
function dependencyAnalysisEnabled(): boolean {
  return configuration().get<boolean>('project.dependencyAnalysis', true)
}

/**
 * Surveillance continue des fichiers du projet (phase 3).
 *
 * Désactivée, l'extension retrouve exactement le comportement de la
 * phase 2 : analyse à la sauvegarde du fichier ouvert, et balayage de
 * projet à la demande.
 */
function monitoringEnabled(): boolean {
  return configuration().get<boolean>('monitoring.enabled', true)
}

/**
 * Anti-rebond de la surveillance, en millisecondes.
 *
 * Borné des deux côtés : en dessous de 200 ms, une frappe rapide
 * déclencherait une analyse par caractère sur les éditeurs qui
 * sauvegardent automatiquement ; au-delà de 10 s, la surveillance
 * cesserait d'être perçue comme continue.
 */
function monitoringDebounceMs(): number {
  const configured = configuration().get<number>(
    'monitoring.debounceMs',
    DEFAULT_DEBOUNCE_MS
  )
  if (!Number.isFinite(configured)) {
    return DEFAULT_DEBOUNCE_MS
  }
  return Math.min(10_000, Math.max(200, Math.round(configured)))
}

/**
 * Analyse de sécurité d'API (phase 5).
 *
 * **Entièrement locale** : la détection tourne sur cette machine, et ce
 * qui part au backend est un constat — chemin, ligne, règle, extrait de
 * déclaration expurgé — jamais le contenu du fichier analysé.
 */
function apiSecurityEnabled(): boolean {
  return configuration().get<boolean>('project.apiSecurity', true)
}

/**
 * Analyse de sécurité des changements Git (phase 4).
 *
 * Désactivée, aucun dépôt n'est observé et la section « Changements Git »
 * disparaît de la vue. L'analyse de projet et la surveillance continue
 * sont inchangées.
 */
function gitEnabled(): boolean {
  return configuration().get<boolean>('git.enabled', true)
}

/**
 * Protection avant push : `off`, `warn` (défaut) ou `block`.
 *
 * `warn` par défaut, délibérément : un outil qui bloque sans qu'on le lui
 * ait demandé est désinstallé, pas corrigé. Une valeur inconnue retombe
 * sur `warn`, jamais sur `block` — un réglage mal orthographié ne doit
 * pas durcir la protection à l'insu de l'utilisateur.
 */
function prePushMode(): PrePushMode {
  return normalizeMode(configuration().get<string>('git.prePushProtection', 'warn'))
}

/**
 * Plafond de fichiers analysés avant de passer en mode réduit.
 *
 * Au-delà — un `git checkout` de branche, une fusion — seuls les premiers
 * sont examinés, et le résumé l'annonce.
 */
function gitMaxChangedFiles(): number {
  const configured = configuration().get<number>(
    'git.maxChangedFiles',
    DEFAULT_MAX_CHANGED_FILES
  )
  if (!Number.isFinite(configured)) {
    return DEFAULT_MAX_CHANGED_FILES
  }
  return Math.min(500, Math.max(1, Math.round(configured)))
}

/** Budget d'une vérification avant push. Objectif : sous trois secondes. */
function gitBudgetMs(): number {
  const configured = configuration().get<number>('git.budgetMs', DEFAULT_BUDGET_MS)
  if (!Number.isFinite(configured)) {
    return DEFAULT_BUDGET_MS
  }
  return Math.min(10_000, Math.max(250, Math.round(configured)))
}

/**
 * Comparaison des dépendances à la base publique de vulnérabilités.
 *
 * Seule fonction de la phase 2 qui fait sortir quelque chose de la
 * machine — des noms et des versions de paquets, rien d'autre. Réglage
 * distinct des deux précédents pour cette seule raison : on peut vouloir
 * l'inventaire sans l'appel externe.
 *
 * Désactivé, le contexte affiche « vérification désactivée », jamais
 * « aucune vulnérabilité ».
 */
function vulnerabilityCheckEnabled(): boolean {
  return configuration().get<boolean>('project.vulnerabilityCheck', true)
}

/**
 * Valide l'adresse configurée.
 *
 * Un refus ne modifie **pas** le réglage de l'utilisateur : l'appelant se
 * replie sur la boucle locale, ce qui est l'option la plus restrictive, et
 * `announceBackend` explique pourquoi. Corriger le réglage en silence
 * masquerait une configuration hostile derrière un fonctionnement normal.
 */
function resolveBackendUrl(): BackendUrlVerdict {
  return validateBackendUrl(configuredBackendUrl(), {
    allowRemote: allowRemoteBackendEnabled(),
  })
}

/**
 * Rend visible l'adresse réellement utilisée.
 *
 * Trois situations, trois traitements :
 *
 * - **locale** : le cas normal, une ligne dans le canal de sortie ;
 * - **distante** : avertissement à l'écran *et* marque permanente dans la
 *   barre d'état — le code quitte la machine, cela ne doit pas s'oublier ;
 * - **refusée** : erreur à l'écran, avec la raison et le repli annoncé.
 */
function announceBackend(verdict: BackendUrlVerdict): void {
  if (!verdict.ok) {
    log(`adresse du backend refusée (${verdict.reason}) — ${verdict.message}`)
    statusBar.setBackendUnavailable()
    // Deux messages : ce qui est refusé, puis ce qui se passe malgré tout.
    void vscode.window.showErrorMessage(verdict.message)
    void vscode.window.showWarningMessage(
      FR.backendUrl.fallback(DEFAULT_BACKEND_URL)
    )
    return
  }

  if (shouldAdvertiseBackend(verdict)) {
    log(`backend distant autorisé : ${verdict.host}`)
    statusBar.setRemoteBackend(verdict.host)
    void vscode.window.showWarningMessage(FR.backendUrl.remoteActive(verdict.host))
    return
  }

  statusBar.clearRemoteBackend()
  log(`backend local : ${verdict.host}`)
}

function autoScanEnabled(): boolean {
  return configuration().get<boolean>('autoScan', true)
}

function scanOnSaveEnabled(): boolean {
  return configuration().get<boolean>('scanOnSave', true)
}

function syncOnStartupEnabled(): boolean {
  return configuration().get<boolean>('syncOnStartup', true)
}

// --------------------------------------------------------------------------
// Backend
// --------------------------------------------------------------------------

/**
 * Vérifie la disponibilité du backend.
 *
 * Un backend absent ne désactive rien : l'extension reste chargée et
 * réessaiera à la prochaine analyse.
 */
async function checkBackend(options: {
  notifyOnSuccess: boolean
  /** Reprendre l'historique si le backend répond. */
  syncHistory: boolean
}): Promise<void> {
  try {
    const health = await client.health()
    log(
      `backend disponible — API ${health.api_version}, ${health.rules_count} règles ` +
        `(v${health.rules_version}), enrichissement IA : ${
          health.ai_enabled ? 'activé' : 'désactivé'
        }`
    )

    // C'est le backend qui décide : « Analyze with AI » n'apparaît que
    // lorsqu'il annonce l'IA active.
    codeAiEnabled = health.ai_enabled

    // Phase 6 : l'assistant de sécurité a son propre état. Consulté sans
    // bloquer ni échouer : un backend plus ancien répond 404, un backend
    // sans clé API répond « indisponible », et dans les deux cas la
    // détection continue à l'identique.
    await refreshSecurityAiHealth(health.project_security_enabled === true)
    setAiContext(codeAiEnabled || securityAiAvailable())

    // Capacite phase 2 annoncee par le backend. Un backend plus ancien
    // repond `undefined` : on le lit comme « absent » plutot que comme
    // « actif », pour ne pas parcourir tout le disque avant un 404.
    projectSecurityEnabled = health.project_security_enabled === true
    log(
      `securite projet ${
        projectSecurityEnabled ? 'disponible' : 'non portee par ce backend'
      }`
    )

    // Backend joignable : c'est le moment de reprendre l'historique. Fait
    // ici plutôt qu'en parallèle de la vérification, pour ne pas lancer
    // une requête vers un serveur dont on ignore encore s'il répond.
    if (options.syncHistory && syncOnStartupEnabled()) {
      await refreshFindings(false)
    }

    if (options.notifyOnSuccess) {
      void vscode.window.showInformationMessage(
        FR.backendCheckOk(
          client.url,
          health.api_version,
          health.rules_count,
          health.ai_enabled
        )
      )
    }
  } catch (error) {
    const message = error instanceof BackendError ? error.message : FR.errors.unexpected
    const detail = error instanceof BackendError ? error.detail : undefined

    log(`backend injoignable — ${message}${detail ? ` (${detail})` : ''}`)
    codeAiEnabled = false
    securityAiHealth = undefined
    setSecurityAiContext()
    setAiContext(false)

    if (options.notifyOnSuccess) {
      void vscode.window.showWarningMessage(FR.backendCheckFailed(client.url, message))
    } else {
      // Au démarrage, l'information reste discrète : la barre d'état et
      // le canal de sortie suffisent.
      log(FR.backendUnavailable(message))
    }
  }
}

/** Pilote la visibilité des actions IA dans les menus. */
function setAiContext(enabled: boolean): void {
  aiEnabled = enabled
  void vscode.commands.executeCommand('setContext', 'wazuhSecurity.aiEnabled', enabled)
}

// --------------------------------------------------------------------------
// Assistant IA de sécurité (phase 6)
// --------------------------------------------------------------------------

/**
 * L'assistant est-il utilisable ? Le backend décide (`available`), le
 * réglage utilisateur peut seulement le retirer.
 */
function securityAiAvailable(): boolean {
  return aiAssistantSettingEnabled() && securityAiHealth?.available === true
}

/**
 * Une action IA existe-t-elle pour ce finding ?
 *
 * Un finding de sécurité projet est expliqué par l'assistant ; un finding
 * d'analyse de fichier, par l'enrichissement IA du code. Les deux sont
 * annoncés séparément par le backend.
 */
function aiAvailableFor(finding: CodeFinding): boolean {
  return isProjectFinding(finding) ? securityAiAvailable() : codeAiEnabled
}

// --------------------------------------------------------------------------
// Posture de sécurité (phase 8)
// --------------------------------------------------------------------------

/** Politique CI/CD évaluée pour l'affichage. Inconnue = `warn`. */
function ciPolicyMode() {
  return normalizeCiMode(configuration().get<string>('ci.policy', 'warn'))
}

/**
 * Ce que la section « Posture » affiche. `undefined` = pas de section :
 * ni projet établi, ni posture lue, ni erreur à dire.
 */
function postureInputs(): PostureInputs | undefined {
  if (!postureState.posture && !postureState.error) {
    return undefined
  }
  return {
    ...postureState,
    git: gitSecurity?.summary(),
    monitoring: monitor?.isRunning ? monitor.state : 'off',
  }
}

function schedulePostureRefresh(): void {
  if (postureTimer) {
    clearTimeout(postureTimer)
  }
  postureTimer = setTimeout(() => {
    postureTimer = undefined
    void refreshPosture()
  }, 1500)
}

/**
 * Relit posture et contrôle CI chez le backend.
 *
 * Deux lectures, aucun balayage : la posture décrit ce que les moteurs ont
 * déjà établi. Une panne ne casse rien — la section dit « indisponible ».
 */
async function refreshPosture(): Promise<void> {
  const projectUid = project.projectUid()
  if (!projectUid || !projectSecurityEnabled) {
    postureState = {}
    projectView?.provider.refresh()
    return
  }

  try {
    const [posture, ci] = await Promise.all([
      client.getPosture(projectUid),
      client.ciCheck(projectUid, { mode: ciPolicyMode() }),
    ])
    // Cloisonnement : le dossier a pu changer pendant l'aller-retour.
    if (project.projectUid() !== projectUid) {
      return
    }
    postureState = { posture, ci }
  } catch (error) {
    const message = error instanceof BackendError ? error.message : FR.errors.unexpected
    postureState = { error: message }
    log(`posture de sécurité illisible — ${message}`)
  }
  projectView?.provider.refresh()
}

/** La remédiation assistée (phase 7) est-elle annoncée par le backend ? */
function securityFixAvailable(): boolean {
  return securityAiAvailable() && securityAiHealth?.fix_available === true
}

function setSecurityAiContext(): void {
  const available = securityAiAvailable()
  void vscode.commands.executeCommand(
    'setContext',
    'wazuhSecurity.securityFixEnabled',
    securityFixAvailable()
  )
  void vscode.commands.executeCommand(
    'setContext',
    'wazuhSecurity.securityAiEnabled',
    available
  )
  void vscode.commands.executeCommand(
    'setContext',
    'wazuhSecurity.securityChatEnabled',
    available && securityAiHealth?.chat_available === true
  )
}

/**
 * Relit l'état de l'assistant. Ne lève jamais.
 *
 * Un backend plus ancien répond 404, un backend sans clé API répond
 * « indisponible » : dans les deux cas l'assistant est simplement
 * absent, et rien d'autre ne change.
 */
async function refreshSecurityAiHealth(projectSecuritySupported: boolean): Promise<void> {
  if (!projectSecuritySupported || !aiAssistantSettingEnabled()) {
    securityAiHealth = undefined
    setSecurityAiContext()
    return
  }

  try {
    securityAiHealth = await client.securityAiHealth()
    log(
      securityAiHealth.available
        ? `assistant IA de sécurité disponible (modèle ${securityAiHealth.model})`
        : `assistant IA de sécurité indisponible — ${securityAiHealth.reason}`
    )
  } catch (error) {
    securityAiHealth = undefined
    const detail = error instanceof BackendError ? `HTTP ${error.status}` : String(error)
    log(`assistant IA de sécurité non porté par ce backend (${detail})`)
  }
  setSecurityAiContext()
}

/**
 * Ouvre la fenêtre de l'assistant et renvoie son contrôleur.
 *
 * Refuse proprement — sans rien appeler — quand le réglage l'interdit ou
 * qu'aucun projet n'est établi. Quand le backend annonce l'assistant
 * indisponible, la fenêtre s'ouvre quand même et dit pourquoi : c'est
 * plus utile qu'une commande muette.
 */
async function openSecurityAssistant() {
  if (!aiAssistantSettingEnabled()) {
    void vscode.window.showInformationMessage(FR.assistant.disabledBySetting)
    return undefined
  }
  if (!project.projectUid()) {
    void vscode.window.showInformationMessage(FR.assistant.noProject)
    return undefined
  }

  const assistant = SecurityAiPanel.open({
    backend: client,
    projectUid: () => project.projectUid(),
    log,
  })
  const health = await assistant.refreshHealth()
  securityAiHealth = health
  setSecurityAiContext()
  return health?.available ? assistant : undefined
}

/**
 * Reprend l'historique du backend et remet l'affichage en cohérence.
 *
 * Un seul chemin pour les deux usages : la synchronisation silencieuse du
 * démarrage et la commande « Refresh Findings ». Tout le travail est fait
 * par `syncHistory`, qui n'utilise que des routes existantes.
 */
async function refreshFindings(notify: boolean): Promise<void> {
  await syncHistory(
    { client, diagnostics, store, statusBar, log },
    // Historique restreint au projet ouvert : sans ce filtre, la vue
    // afficherait les findings de tous les projets analyses par ce backend.
    // `undefined` conserve le comportement anterieur — utile pour un
    // fichier ouvert hors de tout dossier.
    { notify, projectUid: project.projectUid() }
  )

  // Les findings de sécurité projet suivent le même chemin : ils sont
  // repris depuis le backend plutôt que reproduits par un nouveau
  // parcours du disque, qui coûterait autant que le premier.
  await resumeSecurityFindings()
}

/**
 * Document sur lequel portent « Scan Current File » et « Analyze with AI ».
 *
 * L'éditeur actif peut être le panneau Output — un éditeur de texte à
 * part entière, de langage `Log` : `pickScanTarget` se rabat alors sur le
 * fichier encore visible à l'écran.
 */
function activeSourceDocument(): vscode.TextDocument | undefined {
  return pickScanTarget(
    vscode.window.activeTextEditor?.document,
    vscode.window.visibleTextEditors.map((editor) => editor.document)
  )
}

/**
 * Relance une analyse en demandant l'enrichissement IA au backend.
 *
 * Depuis la vue, la cible est le fichier du finding sélectionné ; depuis
 * la palette, c'est l'éditeur actif.
 */
async function analyzeWithAi(argument: unknown): Promise<void> {
  const uid = findingUidOf(argument)
  let document: vscode.TextDocument | undefined

  if (uid) {
    const finding = store.get(uid)

    // Phase 6 : un finding de sécurité projet (secret, dépendance, API)
    // est expliqué par l'assistant, sur la base de ce que le moteur a
    // déjà établi. Aucun nouveau balayage, aucun contenu de fichier
    // transmis : seul l'identifiant part.
    if (finding && isProjectFinding(finding)) {
      const assistant = await openSecurityAssistant()
      await assistant?.analyze(finding.finding_uid, finding.title || finding.category_label)
      return
    }

    if (!codeAiEnabled) {
      void vscode.window.showInformationMessage(FR.assistant.notProjectFinding)
      return
    }

    if (finding) {
      const editor = await openInEditor(finding, log)
      document = editor?.document
    }
  }

  document ??= activeSourceDocument()

  if (!document) {
    void vscode.window.showInformationMessage(FR.scanNoDocument)
    return
  }

  log(`analyse IA demandée pour ${document.uri.fsPath} (langage « ${document.languageId} »)`)
  await controller.scanNow(document, { forceAi: true })
}

// --------------------------------------------------------------------------
// Contexte de projet
// --------------------------------------------------------------------------

/**
 * Établit le contexte du projet ouvert.
 *
 * Toujours en arrière-plan, toujours annulable, jamais bloquant pour
 * l'interface : `withProgress` sur la barre d'état plutôt qu'une boîte
 * modale, parce que l'éditeur reste parfaitement utilisable pendant ce
 * temps — l'analyse d'un fichier fonctionne sans contexte de projet.
 *
 * `notify` distingue les deux appelants : la commande explicite doit
 * répondre quelque chose, la découverte d'ouverture reste discrète.
 *
 * `forceSecurity` vient de « Scan Project Security » : l'utilisateur
 * demande explicitement les analyses de la phase 2, même si les réglages
 * les laissent habituellement de côté. Le drapeau ne contourne jamais
 * l'état du backend — une capacité que le serveur n'annonce pas n'est pas
 * exercée.
 */
async function discoverProjectContext(options: {
  notify: boolean
  forceSecurity?: boolean
}): Promise<void> {
  const root = workspaceRoot()
  if (!root) {
    // Aucun dossier ouvert : ce n'est pas une panne. L'analyse reste
    // disponible sur les fichiers ouverts isolément.
    log(FR.project.noWorkspace)
    if (options.notify) {
      void vscode.window.showInformationMessage(FR.project.noWorkspace)
    }
    return
  }

  if (project.isRunning) {
    if (options.notify) {
      void vscode.window.showInformationMessage(FR.project.alreadyRunning)
    }
    return
  }

  discoveryCancellation?.dispose()
  const cancellation = new vscode.CancellationTokenSource()
  discoveryCancellation = cancellation

  try {
    const outcome = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Window,
        title: FR.project.discovering,
        cancellable: true,
      },
      async (progress, progressToken) => {
        // Deux sources d'annulation : la croix de la barre de progression
        // et la désactivation de l'extension. Les deux doivent arrêter le
        // parcours du disque.
        const link = progressToken.onCancellationRequested(() => cancellation.cancel())
        try {
          return await project.discover({
            workspacePath: root,
            git: await detectGit(root),
            ignore: gitignoreMatcher(root),
            security: securityRequest(options.forceSecurity === true),
            isCancelled: () => cancellation.token.isCancellationRequested,
            onProgress: (indexed) => {
              // Les multiples de 500 seulement : rafraîchir à chaque
              // fichier ferait plus de travail d'affichage que de parcours.
              if (indexed % 500 === 0) {
                progress.report({ message: FR.project.discoveringDetail(indexed) })
              }
            },
          })
        } finally {
          link.dispose()
        }
      }
    )

    // Le flux doit être réabonné au projet qui vient d'être établi : sans
    // cela, le backend n'aurait aucun destinataire pour ses findings.
    if (outcome.ok) {
      restartStream()
      applySecurityFindings(outcome.securityFindings)
      // La surveillance reprend l'etat de ce parcours : index pour le
      // cache d'empreintes, detail par fichier pour le registre. Sans
      // cette adoption, elle refuse de soumettre quoi que ce soit.
      monitor.adopt(outcome)
      syncMonitoring()
    }

    if (options.notify || !outcome.ok) {
      if (outcome.ok || outcome.cancelled) {
        // Le bilan de sécurité complète le message de découverte quand une
        // analyse a réellement eu lieu. Son absence n'est pas silencieuse
        // par négligence : « rien cherché » et « rien trouvé » ne doivent
        // pas produire la même phrase.
        const message = outcome.securityMessage
          ? `${outcome.message} ${outcome.securityMessage}`
          : outcome.message
        void vscode.window.showInformationMessage(message)
      } else {
        void vscode.window.showWarningMessage(outcome.message)
      }
    }

    for (const warning of outcome.warnings) {
      log(`avertissement de sécurité projet : ${warning}`)
    }
  } finally {
    if (discoveryCancellation === cancellation) {
      discoveryCancellation = undefined
    }
    cancellation.dispose()
  }
}


// --------------------------------------------------------------------------
// Sécurité projet (phase 2)
// --------------------------------------------------------------------------

/**
 * Analyses à mener pendant le prochain parcours.
 *
 * Trois conditions se combinent, et aucune n'est contournable :
 *
 *     backend        il doit annoncer la capacité — sinon on parcourrait
 *                    tout le disque pour se faire répondre 404
 *     réglage        l'utilisateur décide de ce qui tourne chez lui
 *     commande       « Scan Project Security » force les deux analyses,
 *                    sans jamais forcer la sortie réseau
 *
 * `forced` relève les réglages d'analyse locale, **pas** celui de la base
 * de vulnérabilités : interroger un service externe reste une décision
 * distincte, et une commande de balayage ne vaut pas consentement à faire
 * sortir la liste des dépendances de la machine.
 */
function securityRequest(forced: boolean):
  | {
      secrets: boolean
      dependencies: boolean
      api: boolean
      checkVulnerabilities: boolean
    }
  | undefined {
  if (!projectSecurityEnabled) {
    if (forced) {
      void vscode.window.showWarningMessage(FR.security.disabledByBackend)
    }
    return undefined
  }

  const secrets = forced || secretDetectionEnabled()
  const dependencies = forced || dependencyAnalysisEnabled()
  const api = forced || apiSecurityEnabled()

  if (!secrets && !dependencies && !api) {
    return undefined
  }

  return {
    secrets,
    dependencies,
    api,
    checkVulnerabilities: vulnerabilityCheckEnabled(),
  }
}

/**
 * Publie les findings de sécurité projet dans la vue et dans « Problems ».
 *
 * Les findings d'analyse de fichier ne sont pas touchés : les deux
 * familles cohabitent dans un seul registre et se remplacent séparément
 * (voir `security/findingAdapter.ts`).
 *
 * Aucune notification n'est déclenchée ici : elles passent par le
 * `NotificationCenter`, qui dédoublonne et regroupe. Un balayage de
 * projet peut remonter des dizaines de secrets, et une bulle par secret
 * rendrait l'extension insupportable — donc muette, parce qu'on la
 * désactiverait.
 */
function applySecurityFindings(findings: readonly SecurityFinding[]): void {
  // Conserve pour la phase 4 : l'analyse Git **classe** ces findings, elle
  // n'en produit pas. Une copie en lecture seule, pas un second registre.
  projectSecurityFindings = findings
  const view = toViewFindings(findings)

  store.replaceProjectFindings(view)
  projectDiagnostics.publish(findings)
  notifications.consider(view)

  log(
    `sécurité projet : ${view.length} signalement(s) publié(s) dans la vue ` +
      `et dans Problems`
  )
}

/**
 * Reprend les findings de sécurité déjà enregistrés, sans nouveau balayage.
 *
 * Appelée quand un projet déjà connu est rouvert : afficher ce qu'on
 * savait de la session précédente vaut mieux qu'une vue vide pendant
 * qu'un balayage tourne.
 */
async function resumeSecurityFindings(): Promise<void> {
  const projectUid = project.projectUid()
  if (!projectUid || !projectSecurityEnabled) {
    return
  }

  const findings = await security.fetchExisting(projectUid)
  if (findings.length > 0) {
    applySecurityFindings(findings)
  }
}

/**
 * Métadonnées Git du dossier : présence et hôte du remote.
 *
 * Passe par l'extension `vscode.git` plutôt que par une commande système.
 * L'extension n'exécute aucun processus, et cette règle ne cède pas pour
 * une information d'affichage. Si l'API n'est pas disponible, on se rabat
 * sur la présence du dossier `.git`, qui suffit à répondre « dépôt
 * détecté » sans rien lancer.
 *
 * Seul l'hôte du remote est conservé : une URL de remote complète peut
 * contenir un jeton d'accès.
 */
async function detectGit(root: string): Promise<GitMetadata> {
  const gitFolder = vscode.Uri.joinPath(vscode.Uri.file(root), '.git')
  if (!(await pathExists(gitFolder))) {
    return { detected: false, remote_host: null }
  }

  try {
    const extension = vscode.extensions.getExtension<GitExtensionShape>('vscode.git')
    const exports = extension?.isActive
      ? extension.exports
      : await extension?.activate()

    const api = exports?.getAPI?.(1)
    const repository = api?.repositories?.find((candidate) =>
      root.startsWith(candidate.rootUri.fsPath)
    )
    const remote = repository?.state?.remotes?.[0]

    return {
      detected: true,
      remote_host: remoteHostOf(remote?.fetchUrl ?? remote?.pushUrl),
    }
  } catch (error) {
    // API Git absente ou en erreur : la présence du dépôt est déjà établie,
    // et l'hôte n'est qu'un complément.
    log(`API Git indisponible : ${error instanceof Error ? error.name : 'inconnue'}`)
    return { detected: true, remote_host: null }
  }
}

/** Forme minimale de l'API `vscode.git` réellement utilisée ici. */
interface GitExtensionShape {
  getAPI?: (version: number) => {
    repositories?: {
      rootUri: vscode.Uri
      state?: { remotes?: { fetchUrl?: string; pushUrl?: string }[] }
    }[]
  }
}

/**
 * Hôte d'une URL de remote. `null` dès qu'un doute subsiste.
 *
 * L'implémentation vit désormais dans `git/remoteUrl.ts`, avec le reste
 * de l'expurgation des métadonnées Git (phase 4). Elle est réexportée ici
 * parce que `detectGit` s'en sert depuis la phase 1, et que la déplacer
 * sans laisser ce point d'entrée casserait un appelant pour rien.
 */
export { remoteHostOf }

async function pathExists(uri: vscode.Uri): Promise<boolean> {
  try {
    await vscode.workspace.fs.stat(uri)
    return true
  } catch {
    return false
  }
}

/**
 * `.gitignore` du projet, réutilisé pour la découverte.
 *
 * Le même lecteur que celui du filtre de documents : un fichier ignoré par
 * Git ne doit pas plus apparaître dans l'index que partir au backend. Le
 * fail-open du lecteur est conservé — un motif mal compris laisse le
 * fichier indexé, jamais écarté à tort.
 */
function gitignoreMatcher(root: string | undefined): {
  ignores: (relativePath: string) => boolean
} {
  const matcher = GitignoreMatcher.load(root)
  return { ignores: (relativePath) => matcher.ignores(relativePath) }
}

// --------------------------------------------------------------------------
// Sécurité des changements Git (phase 4)
// --------------------------------------------------------------------------

/**
 * Findings de sécurité projet actuellement connus.
 *
 * L'analyse Git les **classe** — introduit / préexistant — sans jamais en
 * produire. C'est ce qui garantit qu'il n'existe qu'une architecture de
 * findings dans l'extension.
 */
let projectSecurityFindings: readonly SecurityFinding[] = []

/**
 * Recalcule l'attribution des findings au changement en cours.
 *
 * Ne relance **aucune** découverte de projet : c'est tout l'intérêt. Un
 * changement de branche touche parfois des milliers de fichiers, et c'est
 * précisément le moment où un parcours complet coûterait le plus cher.
 */
async function refreshGitAnalysis(): Promise<void> {
  if (!gitEnabled()) {
    return
  }

  await gitSecurity.analyze({ budgetMs: gitBudgetMs() })
  // La vue « Project » porte le bilan : elle est redessinée ici, parce
  // que le contexte de projet n'a pas bougé et n'émettra donc rien.
  projectView?.provider.refresh()
}

/** Aligne la surveillance Git sur le réglage et sur le dossier ouvert. */
function syncGitMonitoring(): void {
  if (!gitMonitor) {
    return
  }

  if (gitEnabled() && workspaceRoot()) {
    void gitMonitor.start().then(() => refreshGitAnalysis())
    return
  }

  gitMonitor.stop()
  gitSecurity?.clear()
  projectView?.provider.refresh()
}

/**
 * Ouvre le finding qui motive un avertissement avant push.
 *
 * Passe par la commande existante quand le finding est dans le registre ;
 * sinon — cas d'un secret détecté localement et pas encore soumis — ouvre
 * directement le fichier à la ligne. Aucune preuve n'est affichée.
 */
async function revealAttributed(attributed: AttributedFinding): Promise<void> {
  const { finding } = attributed

  if (store.get(finding.id)) {
    await vscode.commands.executeCommand('wazuhSecurity.openFinding', finding.id)
    return
  }

  const root = workspaceRoot()
  if (!root || !finding.file) {
    return
  }

  try {
    const document = await vscode.workspace.openTextDocument(
      vscode.Uri.joinPath(vscode.Uri.file(root), ...finding.file.split('/'))
    )
    const line = Math.max(0, (finding.line_start || 1) - 1)
    await vscode.window.showTextDocument(document, {
      selection: new vscode.Range(line, 0, line, 0),
    })
  } catch {
    // Fichier introuvable ou déplacé : le résumé reste affiché dans la vue.
  }
}

// --------------------------------------------------------------------------
// Flux temps réel
// --------------------------------------------------------------------------

function startStream(): void {
  stream = new StreamClient({
    baseUrl: client.url,
    // Un seul type d'événement nous concerne. Les alertes Wazuh et les
    // notifications IA passent sur le même flux : elles sont écartées par
    // le client lui-même, sans même être décodées.
    events: ['code_finding'],
    onEvent: (event) => controller.applyStreamEvent(event),
    onLog: (message) => log(message),
    authHeader: () => token.authorizationHeader(),
    // Résolu à chaque connexion : le dossier ouvert peut changer, et le
    // backend n'adresse les findings d'un projet qu'aux abonnés qui l'ont
    // déclaré. Sans projet, ce flux ne recevra aucun `code_finding` — et
    // c'est voulu : c'est ce qui empêche un abonné de capter ceux des autres.
    projectUid: () => project.projectUid(),
  })
  stream.start()
}

function restartStream(): void {
  stream?.dispose()
  stream = undefined
  startStream()
}

// --------------------------------------------------------------------------
// Divers
// --------------------------------------------------------------------------

function reportWorkspace(): void {
  const root = workspaceRoot()
  if (root) {
    log(`workspace : ${vscode.workspace.workspaceFolders?.[0]?.name ?? root}`)
    return
  }

  // Aucun dossier ouvert : l'extension reste utilisable sur les fichiers
  // enregistrés qu'on ouvre isolément.
  log(FR.noWorkspace)
}

function log(message: string): void {
  const stamp = new Date().toISOString().slice(11, 19)
  output.appendLine(`[${stamp}] ${message}`)
}

/**
 * Trace de diagnostic dans le canal « Wazuh Security ».
 *
 * Le canal de sortie est fait pour ça : rien n'est affiché à l'écran, et
 * quand une commande semble sans effet, la trace dit exactement à quelle
 * étape le traitement s'est arrêté. Aucun contenu de fichier n'y passe.
 */
function debug(message: string): void {
  log(`[WAZUH DEBUG] ${message}`)
}
