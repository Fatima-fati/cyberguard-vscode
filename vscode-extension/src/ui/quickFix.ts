/**
 * Actions rapides sur un finding : corriger, ignorer, consulter le détail.
 *
 * Trois règles non négociables :
 *
 * 1. **Aucune correction n'est appliquée sans confirmation explicite.**
 *    Une fenêtre modale montre la ligne avant et après ; tant que
 *    l'utilisateur n'a pas cliqué « Appliquer », rien ne bouge.
 * 2. **C'est l'éditeur qui écrit, jamais le backend.** La modification
 *    passe par un `WorkspaceEdit` : elle est annulable par Ctrl+Z et
 *    visible dans le diff Git, contrairement à une écriture serveur.
 *    Aucun `fs.writeFile`, aucune commande shell, aucun accès distant.
 * 3. **On ne recouvre jamais le travail du développeur.** Les contrôles
 *    de `fixGuard.ts` sont joués deux fois : avant d'interroger le
 *    backend, puis de nouveau juste avant d'écrire — le document a pu
 *    changer pendant la requête et pendant que la modale était ouverte.
 *
 * Enchaînement complet :
 *
 *     finding → code action → confirmation → proposition backend
 *            → contrôles → WorkspaceEdit → sauvegarde → décision
 *            → nouvelle analyse → diagnostics et barre d'état à jour
 */

import * as path from 'node:path'
import * as vscode from 'vscode'

import { BackendClient, BackendError, type CodeFinding } from '../api/backendClient'
import { contentHash } from '../analysis/contentHash'
import {
  validateFix,
  validateTarget,
  type DocumentState,
  type FixVerdict,
} from '../analysis/fixGuard'
import type { DiagnosticsProvider } from '../diagnostics/provider'
import type { FindingsStore } from '../state/findingsStore'
import type { StatusBar } from './statusBar'
import { FR } from '../i18n/fr'

/**
 * Identité déclarée au backend dans `POST /findings/{uid}/decision`.
 *
 * Permet de distinguer, dans l'historique, ce qui vient de l'éditeur de
 * ce qui vient de l'interface web.
 */
const ACTOR = 'vscode'

export interface ActionContext {
  client: BackendClient
  diagnostics: DiagnosticsProvider
  statusBar: StatusBar
  /** Registre de la vue « Security », tenu à jour par les décisions. */
  store: FindingsStore
  /**
   * Relance une analyse du document après une correction.
   *
   * Injectée plutôt qu'importée : c'est le `ScanController` qui la
   * fournit, et il dépend déjà de ce module par les diagnostics.
   */
  rescan: (document: vscode.TextDocument) => Promise<void>
  log: (message: string) => void
}

/** Diagnostic auquel l'identifiant du finding a été rattaché. */
type TaggedDiagnostic = vscode.Diagnostic & { findingUid?: string }

// --------------------------------------------------------------------------
// Fournisseur d'actions
// --------------------------------------------------------------------------

export class SecurityCodeActionProvider implements vscode.CodeActionProvider {
  static readonly metadata: vscode.CodeActionProviderMetadata = {
    providedCodeActionKinds: [vscode.CodeActionKind.QuickFix],
  }

  private readonly diagnostics: DiagnosticsProvider

  constructor(diagnostics: DiagnosticsProvider) {
    this.diagnostics = diagnostics
  }

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    // On part des diagnostics présents sous le curseur, en ne retenant que
    // les nôtres : les actions ne doivent pas polluer celles des autres
    // extensions.
    const uids = new Set(
      context.diagnostics
        .filter((diagnostic) => diagnostic.source === FR.diagnosticSource)
        .map((diagnostic) => (diagnostic as TaggedDiagnostic).findingUid)
        .filter((uid): uid is string => Boolean(uid))
    )

    const findings =
      uids.size > 0
        ? this.diagnostics
            .findingsFor(document.uri)
            .filter((finding) => uids.has(finding.finding_uid))
        : this.diagnostics.findingsAt(document.uri, range)

    const actions: vscode.CodeAction[] = []

    for (const finding of findings) {
      // Un finding refermé ne propose plus rien : ni correction, ni abandon.
      if (finding.status !== 'open') {
        continue
      }

      // `fix_available` vient du backend : quand il est faux, l'action
      // « Corriger » n'est pas proposée du tout, plutôt que proposée puis
      // refusée après un aller-retour inutile.
      if (finding.fix_available) {
        const fix = new vscode.CodeAction(
          FR.actions.fixTitle(finding.fix_summary || finding.title),
          vscode.CodeActionKind.QuickFix
        )
        fix.command = {
          command: 'wazuhSecurity.applyFix',
          title: FR.actions.fixTitle(finding.fix_summary || finding.title),
          arguments: [finding.finding_uid],
        }
        fix.isPreferred = true
        actions.push(fix)
      }

      const detail = new vscode.CodeAction(
        FR.actions.detailTitle,
        vscode.CodeActionKind.QuickFix
      )
      detail.command = {
        command: 'wazuhSecurity.showFindingDetail',
        title: FR.actions.detailTitle,
        arguments: [finding.finding_uid],
      }
      actions.push(detail)

      const dismiss = new vscode.CodeAction(
        FR.actions.dismissTitle,
        vscode.CodeActionKind.QuickFix
      )
      dismiss.command = {
        command: 'wazuhSecurity.dismissFinding',
        title: FR.actions.dismissTitle,
        arguments: [finding.finding_uid],
      }
      actions.push(dismiss)
    }

    return actions
  }
}

// --------------------------------------------------------------------------
// Localisation d'un finding
// --------------------------------------------------------------------------

/**
 * Retrouve un finding.
 *
 * Deux registres, par ordre de précision : les diagnostics du document
 * ouvert d'abord, puis la vue « Security » — qui connaît aussi les
 * fichiers refermés depuis un balayage du workspace. Le document n'est
 * retourné que s'il est effectivement ouvert.
 */
function locate(
  context: ActionContext,
  findingUid: string
): { finding: CodeFinding; document: vscode.TextDocument | undefined } | undefined {
  const located = context.diagnostics.findByUid(findingUid)

  if (located) {
    return {
      finding: located.finding,
      document: vscode.workspace.textDocuments.find(
        (candidate) => candidate.uri.toString() === located.uri.toString()
      ),
    }
  }

  const known = context.store.get(findingUid)
  if (!known) {
    void vscode.window.showWarningMessage(FR.actions.findingUnknown)
    return undefined
  }

  return { finding: known, document: undefined }
}

/** Comme `locate`, mais exige un document ouvert : la correction y écrit. */
function locateOpen(
  context: ActionContext,
  findingUid: string
): { finding: CodeFinding; document: vscode.TextDocument } | undefined {
  const located = locate(context, findingUid)
  if (!located) {
    return undefined
  }
  if (!located.document) {
    void vscode.window.showWarningMessage(FR.actions.documentClosed)
    return undefined
  }
  return { finding: located.finding, document: located.document }
}

// --------------------------------------------------------------------------
// Photographie du document, pour les contrôles
// --------------------------------------------------------------------------

/**
 * Le fichier relève-t-il du workspace ouvert ?
 *
 * Un fichier consulté hors de tout dossier ouvert reste corrigeable :
 * l'extension prend ce cas en charge depuis la phase 1. Ce qui est
 * refusé, c'est un fichier étranger alors qu'un workspace est ouvert.
 */
function belongsToWorkspace(uri: vscode.Uri): boolean {
  const folders = vscode.workspace.workspaceFolders
  if (!folders || folders.length === 0) {
    return true
  }
  return vscode.workspace.getWorkspaceFolder(uri) !== undefined
}

/**
 * État courant du document, tel que le voient les contrôles.
 *
 * Recalculé à chaque appel : c'est tout l'intérêt, l'état d'il y a deux
 * secondes ne prouve rien.
 */
function snapshot(
  context: ActionContext,
  document: vscode.TextDocument,
  line: number
): DocumentState {
  const lineIndex = line - 1
  const withinBounds = lineIndex >= 0 && lineIndex < document.lineCount

  return {
    scheme: document.uri.scheme,
    inWorkspace: belongsToWorkspace(document.uri),
    lineCount: document.lineCount,
    currentLineText: withinBounds ? document.lineAt(lineIndex).text : undefined,
    currentHash: contentHash(document.getText()),
    analyzedHash: context.diagnostics.analyzedHash(document.uri),
  }
}

/** Affiche le refus. Une dérive de fichier a son message, et lui seul. */
function reportRefusal(context: ActionContext, verdict: FixVerdict, rule: string): void {
  if (verdict.ok) {
    return
  }

  context.log(`correction refusée pour ${rule} — ${verdict.reason}`)

  if (verdict.fileChanged) {
    void vscode.window.showWarningMessage(FR.fix.fileChanged)
    return
  }

  void vscode.window.showInformationMessage(verdict.reason)
}

// --------------------------------------------------------------------------
// Correction
// --------------------------------------------------------------------------

/**
 * Applique un correctif, après confirmation.
 *
 * Enchaînement : contrôles → proposition du backend (lecture seule) →
 * confirmation modale → **contrôles rejoués** → `WorkspaceEdit` →
 * sauvegarde → décision → nouvelle analyse.
 */
export async function applyFix(
  context: ActionContext,
  findingUid: string
): Promise<void> {
  // 1. Le document doit exister et être ouvert dans l'éditeur.
  const located = locateOpen(context, findingUid)
  if (!located) {
    return
  }

  const { finding, document } = located
  const line = finding.location.line_start

  // 2-5. Fichier local, workspace, finding ouvert, contenu conforme à
  //      l'analyse, ligne existante. Inutile de déranger le backend si
  //      l'un de ces points est déjà en défaut.
  const before = validateTarget(
    { status: finding.status, line },
    snapshot(context, document, line)
  )
  if (!before.ok) {
    reportRefusal(context, before, finding.rule_id)
    return
  }

  const currentLine = before.replacement

  let proposal
  try {
    // Le backend compare la ligne transmise à celle qu'il a analysée et
    // refuse si elle a changé. Il ne modifie aucun fichier : il décrit.
    proposal = await context.client.proposeFix(findingUid, currentLine)
  } catch (error) {
    // Aucune trace d'exécution n'atteint l'utilisateur : le message est
    // déjà traduit, le détail technique part dans le canal de sortie.
    const message = error instanceof BackendError ? error.message : FR.errors.unexpected
    const detail = error instanceof BackendError ? error.detail : undefined
    context.log(
      `correctif indisponible pour ${findingUid} — ${message}${
        detail ? ` (${detail})` : ''
      }`
    )
    void vscode.window.showErrorMessage(FR.actions.noFix(message))
    return
  }

  // 6. La proposition doit être exploitable.
  if (!proposal.available || !proposal.replacement_line) {
    const reason = proposal.blockers[0] ?? FR.actions.fixUnavailable
    context.log(`aucun correctif sûr pour ${finding.rule_id} — ${reason}`)
    void vscode.window.showInformationMessage(FR.actions.noFix(reason))
    return
  }

  const fileName = path.basename(document.uri.fsPath)
  const choice = await vscode.window.showWarningMessage(
    FR.actions.confirmTitle,
    {
      modal: true,
      detail: FR.actions.confirmDetail(
        fileName,
        line,
        proposal.original_line ?? currentLine,
        proposal.replacement_line
      ),
    },
    FR.actions.confirmApply
  )

  // Toute autre réponse — y compris fermer la fenêtre — annule.
  if (choice !== FR.actions.confirmApply) {
    context.log(`correction refusée par l'utilisateur (${finding.rule_id})`)
    return
  }

  // 7. **Contrôles rejoués sur l'état vivant.** La requête a duré, la
  //    modale est restée ouverte : le fichier a pu changer entre-temps.
  //    C'est ici que se joue la promesse de ne rien écraser.
  const verdict = validateFix(
    { status: finding.status, line },
    proposal,
    snapshot(context, document, line)
  )
  if (!verdict.ok) {
    reportRefusal(context, verdict, finding.rule_id)
    return
  }

  // La plage est relue maintenant, pas avant la modale : un décalage de
  // lignes rendrait une plage mémorisée fausse.
  const target = document.lineAt(verdict.line - 1)
  const wasDirty = document.isDirty

  const edit = new vscode.WorkspaceEdit()
  edit.replace(document.uri, target.range, verdict.replacement)

  // `applyEdit` passe par la pile d'annulation de l'éditeur : Ctrl+Z
  // rétablit la ligne d'origine, et le changement apparaît dans le diff.
  const applied = await vscode.workspace.applyEdit(edit)
  if (!applied) {
    context.log(`WorkspaceEdit refusé par l'éditeur (${finding.rule_id})`)
    void vscode.window.showErrorMessage(FR.actions.applyFailed)
    return
  }

  context.log(
    `correction appliquée dans l'éditeur : ${finding.rule_id} ligne ${verdict.line}`
  )
  void vscode.window.showInformationMessage(FR.actions.applied(fileName, verdict.line))

  // Sauvegarde **seulement si nous sommes la seule cause de modification
  // non enregistrée**. Sauver un document que l'utilisateur avait laissé
  // en cours d'édition validerait son travail sans son accord.
  if (!wasDirty && document.isDirty) {
    await document.save()
  }

  // Décision enregistrée côté backend : le finding passe à `fixed`, il
  // n'est jamais supprimé.
  await recordDecision(context, findingUid, document, { status: 'fixed' })

  // Nouvelle analyse : elle rafraîchit diagnostics, barre d'état, vue
  // Security et empreinte de référence, à partir du fichier corrigé.
  await rescanAfterChange(context, document)
}

/**
 * Relance une analyse et signale poliment un échec.
 *
 * Une analyse qui échoue ne remet pas la correction en cause : elle est
 * déjà appliquée et annulable par Ctrl+Z.
 */
async function rescanAfterChange(
  context: ActionContext,
  document: vscode.TextDocument
): Promise<void> {
  try {
    await context.rescan(document)
  } catch (error) {
    context.log(
      `nouvelle analyse impossible après correction — ${
        error instanceof Error ? error.message : String(error)
      }`
    )
    void vscode.window.showWarningMessage(FR.fix.rescanFailed)
  }
}

// --------------------------------------------------------------------------
// Abandon d'un signalement
// --------------------------------------------------------------------------

/**
 * Écarte un signalement jugé faux positif.
 *
 * Deux temps : une confirmation qui dit ce que l'abandon implique, puis
 * une raison facultative. Le finding n'est jamais supprimé — il passe à
 * `dismissed` et reste consultable dans l'historique du backend.
 */
export async function dismissFinding(
  context: ActionContext,
  findingUid: string
): Promise<void> {
  const located = locate(context, findingUid)
  if (!located) {
    return
  }

  const { finding, document } = located

  if (finding.status !== 'open') {
    void vscode.window.showInformationMessage(FR.fix.notOpen)
    return
  }

  const confirmed = await vscode.window.showWarningMessage(
    FR.fix.dismissConfirmTitle,
    {
      modal: true,
      detail: FR.fix.dismissConfirmDetail(
        finding.title || finding.category_label || finding.rule_id,
        finding.file_path,
        finding.location.line_start
      ),
    },
    FR.fix.dismissConfirmAction
  )

  if (confirmed !== FR.fix.dismissConfirmAction) {
    context.log(`abandon annulé par l'utilisateur (${finding.rule_id})`)
    return
  }

  const reason = await vscode.window.showInputBox({
    prompt: FR.actions.dismissPrompt,
    placeHolder: FR.actions.dismissPlaceholder,
  })

  // `undefined` = fenêtre fermée : la confirmation est reprise, on n'écarte
  // rien.
  if (reason === undefined) {
    context.log(`abandon interrompu à la saisie de la raison (${finding.rule_id})`)
    return
  }

  const decided = await recordDecision(context, findingUid, document, {
    status: 'dismissed',
    reason: reason || undefined,
  })

  if (decided) {
    void vscode.window.showInformationMessage(FR.actions.dismissed)
  }
}

/**
 * Enregistre la décision côté backend et met l'affichage à jour.
 *
 * Le finding n'est jamais supprimé : il passe à `fixed` ou `dismissed` et
 * reste consultable dans l'historique du backend. Le diagnostic, lui,
 * disparaît dès que la décision est confirmée par le serveur — jamais
 * avant, pour ne pas afficher un état que le backend ignore.
 */
async function recordDecision(
  context: ActionContext,
  findingUid: string,
  document: vscode.TextDocument | undefined,
  decision: { status: 'dismissed' | 'fixed'; reason?: string }
): Promise<boolean> {
  try {
    const updated = await context.client.decideFinding(findingUid, {
      ...decision,
      actor: ACTOR,
    })

    // La vue « Security » suit la décision même si le fichier n'est pas
    // ouvert : le finding y disparaît, et les compteurs se recalculent.
    context.store.upsert(updated)

    if (document) {
      const counts = context.diagnostics.upsert(document, updated)
      if (counts) {
        context.statusBar.setResult(counts, path.basename(document.uri.fsPath))
      }
    }

    context.log(`finding ${findingUid} marqué ${decision.status} par ${ACTOR}`)
    return true
  } catch (error) {
    const message = error instanceof BackendError ? error.message : FR.errors.unexpected
    const detail = error instanceof BackendError ? error.detail : undefined
    context.log(
      `décision non enregistrée pour ${findingUid} — ${message}${
        detail ? ` (${detail})` : ''
      }`
    )
    void vscode.window.showErrorMessage(FR.scanFailed(message))
    return false
  }
}
