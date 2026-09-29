/**
 * Déroulé d'un correctif assisté dans l'éditeur (phase 7).
 *
 *     « Suggest Fix with AI »
 *        → éligibilité (avant toute lecture)
 *        → extrait borné et expurgé → proposition du backend
 *        → validation locale → aperçu (diff natif + fenêtre de l'assistant)
 *     « Appliquer… »
 *        → confirmation MODALE native
 *        → fichier inchangé depuis la proposition ? sinon : refus
 *        → application bornée, enregistrement, retour arrière si échec
 *        → nouvelle analyse DÉTERMINISTE → verdict affiché
 *
 * Ce module relie l'éditeur au cœur pur (`aiFix.ts`), qui prend toutes
 * les décisions. Il n'enregistre **aucune décision** sur le finding : ni
 * « corrigé », ni « écarté ». Le finding disparaît de la vue si, et
 * seulement si, les moteurs ne le produisent plus.
 */

import * as vscode from 'vscode'

import { BackendError, type BackendClient, type CodeFinding } from '../api/backendClient'
import { resolveFindingUri } from '../analysis/workspacePaths'
import { redactFreeText } from '../ai/aiRedaction'
import type { SecurityFixProposal } from '../ai/aiTypes'
import { failureState, type SecurityAiController } from '../ai/securityAiController'
import { FR } from '../i18n/fr'
import type { ExecutionOutcome } from '../monitor/projectMonitor'
import { isProjectFinding } from '../security/findingAdapter'
import type { FindingsStore } from '../state/findingsStore'
import {
  confirmAndApply,
  buildFixRequest,
  fixEligibility,
  proposedText,
  splitLines,
  stillDetected,
  validateProposal,
  type EditableDocument,
  type Verification,
} from './aiFix'

const R = FR.remediation

/** Schéma des documents d'aperçu : en lecture seule, jamais écrits sur disque. */
export const PREVIEW_SCHEME = 'wazuh-security-fix'

export interface AiFixWorkflowOptions {
  client: BackendClient
  store: FindingsStore
  projectUid: () => string | undefined
  /** Ouvre la fenêtre de l'assistant ; `undefined` si indisponible. */
  openAssistant: () => Promise<SecurityAiController | undefined>
  /** Réanalyse déterministe d'un fichier du projet (surveillance). */
  rescanProjectFile: (relative: string) => Promise<ExecutionOutcome | undefined>
  /** Repli : balayage complet de sécurité projet. */
  fullSecurityScan: () => Promise<void>
  /** Réanalyse d'un document par l'analyse de code. */
  rescanCodeDocument: (document: vscode.TextDocument) => Promise<void>
  log: (message: string) => void
}

interface PendingFix {
  finding: CodeFinding
  uri: vscode.Uri
  proposal: SecurityFixProposal
  baseHash: string
  previewUri: vscode.Uri
  controller: SecurityAiController
}

/** Le document de l'éditeur, vu par `applyBoundedFix`. */
export function editableDocument(document: vscode.TextDocument): EditableDocument {
  const eol = document.eol === vscode.EndOfLine.CRLF ? '\r\n' : '\n'
  return {
    getText: () => document.getText(),
    isDirty: () => document.isDirty,
    replaceLines: async (start, end, lines) => {
      const range = new vscode.Range(start - 1, 0, end - 1, document.lineAt(end - 1).text.length)
      const edit = new vscode.WorkspaceEdit()
      edit.replace(document.uri, range, lines.join(eol))
      return vscode.workspace.applyEdit(edit)
    },
    replaceAll: async (text) => {
      const last = document.lineAt(document.lineCount - 1)
      const edit = new vscode.WorkspaceEdit()
      edit.replace(document.uri, new vscode.Range(0, 0, last.lineNumber, last.text.length), text)
      return vscode.workspace.applyEdit(edit)
    },
    save: async () => document.save(),
  }
}

export class AiFixWorkflow implements vscode.Disposable, vscode.TextDocumentContentProvider {
  private readonly options: AiFixWorkflowOptions
  private readonly previews = new Map<string, string>()
  private readonly emitter = new vscode.EventEmitter<vscode.Uri>()
  readonly onDidChange = this.emitter.event
  private readonly registration: vscode.Disposable
  private pending: PendingFix | undefined
  private sequence = 0

  constructor(options: AiFixWorkflowOptions) {
    this.options = options
    this.registration = vscode.workspace.registerTextDocumentContentProvider(PREVIEW_SCHEME, this)
  }

  /** Contenu d'un aperçu. Local, en mémoire, jamais transmis. */
  provideTextDocumentContent(uri: vscode.Uri): string {
    return this.previews.get(uri.toString()) ?? ''
  }

  dispose(): void {
    this.registration.dispose()
    this.emitter.dispose()
    this.previews.clear()
    this.pending = undefined
  }

  // ---------------- Proposition ----------------

  async suggest(findingUid: string): Promise<void> {
    const finding = this.options.store.get(findingUid)
    if (!finding) {
      void vscode.window.showWarningMessage(FR.actions.findingUnknown)
      return
    }

    const controller = await this.options.openAssistant()
    if (!controller) {
      return
    }
    const projectUid = this.options.projectUid()
    if (!projectUid) {
      return
    }

    this.clearPending()
    const title = finding.title || finding.category_label || finding.rule_id
    const refuse = (message: string, extra: { manualSteps?: string[]; explanation?: string } = {}) => {
      controller.showFix(findingUid, title, { stage: 'refused', message, ...extra })
    }

    // 1. Éligibilité, AVANT de lire quoi que ce soit : un `.env` n'est pas
    //    ouvert pour découvrir ensuite qu'on ne le modifiera pas.
    const eligibility = fixEligibility(finding)
    if (!eligibility.ok) {
      refuse(eligibility.reason)
      return
    }

    // 2. Fichier local, dans le workspace, sans modification en attente.
    const uri = await resolveFindingUri(finding.file_path)
    if (!uri) {
      refuse(R.fileNotFound(finding.file_path))
      return
    }
    if (uri.scheme !== 'file' || !vscode.workspace.getWorkspaceFolder(uri)) {
      refuse(R.notLocal)
      return
    }
    const document = await vscode.workspace.openTextDocument(uri)
    if (document.isDirty) {
      refuse(R.unsaved)
      return
    }

    // 3. Extrait borné et expurgé.
    const text = document.getText()
    const built = buildFixRequest(finding, text, finding.file_path, document.languageId)
    if (!built.ok) {
      refuse(built.reason)
      return
    }

    controller.showFix(findingUid, title, { stage: 'loading' })
    this.options.log(
      `correctif IA demandé pour ${findingUid} (${finding.file_path}, ligne ${built.targetLine}, ` +
        `${built.request.excerpt_lines.length} ligne(s) d'extrait expurgé)`
    )

    let raw: unknown
    try {
      raw = await this.options.client.proposeFixWithAi(projectUid, findingUid, built.request)
    } catch (error) {
      const detail = error instanceof BackendError && error.detail ? error.detail : undefined
      controller.updateFix(findingUid, {
        stage: 'rejected',
        message: detail ?? failureState(error).message,
      })
      return
    }

    // 4. Refus motivé du backend ou du modèle : remédiation manuelle.
    const response = raw as Partial<SecurityFixProposal> | null
    if (response && response.ai_generated === true && response.available === false) {
      controller.updateFix(findingUid, {
        stage: 'refused',
        message: response.refusal || R.unsupported,
        manualSteps: Array.isArray(response.manual_steps) ? response.manual_steps : [],
        explanation: typeof response.explanation === 'string' ? response.explanation : '',
      })
      return
    }

    // 5. Validation locale, sans confiance dans le backend.
    const { lines } = splitLines(text)
    const verdict = validateProposal(raw, {
      findingId: findingUid,
      relativePath: finding.file_path,
      baseHash: built.request.content_hash,
      targetLine: built.targetLine,
      lines,
    })
    if (!verdict.ok) {
      this.options.log(`correctif IA rejeté pour ${findingUid} — ${verdict.reason}`)
      controller.updateFix(findingUid, { stage: 'rejected', message: verdict.reason })
      return
    }

    const proposal = verdict.proposal
    const previewUri = vscode.Uri.from({
      scheme: PREVIEW_SCHEME,
      path: `/${finding.file_path}`,
      query: String(++this.sequence),
    })
    this.previews.set(previewUri.toString(), proposedText(text, proposal))

    this.pending = {
      finding,
      uri,
      proposal,
      baseHash: built.request.content_hash,
      previewUri,
      controller,
    }

    controller.updateFix(findingUid, {
      stage: 'proposed',
      proposal,
      currentLines: lines
        .slice(proposal.start_line - 1, proposal.end_line)
        .map((line) => redactFreeText(line)),
    })

    // Aperçu natif : le diff de l'éditeur, entre le fichier et la
    // proposition. Rien n'est écrit tant que l'utilisateur n'a pas
    // confirmé.
    await this.showDiff()
  }

  async showDiff(): Promise<void> {
    const pending = this.pending
    if (!pending) {
      return
    }
    await vscode.commands.executeCommand(
      'vscode.diff',
      pending.uri,
      pending.previewUri,
      R.diffTitle(pending.finding.file_path),
      { preview: true }
    )
  }

  cancel(): void {
    const pending = this.pending
    if (!pending) {
      return
    }
    pending.controller.updateFix(pending.finding.finding_uid, { stage: 'cancelled' })
    this.options.log(`correctif IA annulé par l'utilisateur (${pending.finding.finding_uid})`)
    this.clearPending()
  }

  // ---------------- Application ----------------

  async apply(): Promise<void> {
    const pending = this.pending
    if (!pending) {
      void vscode.window.showInformationMessage(R.needFresh)
      return
    }
    const { finding, proposal, controller } = pending
    const uid = finding.finding_uid

    const document = await vscode.workspace.openTextDocument(pending.uri)

    // Confirmation native et modale. C'est elle, et non le bouton de la
    // page, qui autorise l'écriture : une page ne peut pas cliquer ici.
    const confirm = async (): Promise<boolean> => {
      const choice = await vscode.window.showWarningMessage(
        R.confirmTitle,
        {
          modal: true,
          detail: R.confirmDetail(finding.file_path, proposal.start_line, proposal.end_line),
        },
        R.confirmApply
      )
      // La proposition a pu être remplacée pendant que la fenêtre était
      // ouverte : seule celle qui a été montrée peut être confirmée.
      return choice === R.confirmApply && this.pending === pending
    }

    const outcome = await confirmAndApply(
      confirm,
      editableDocument(document),
      proposal,
      pending.baseHash,
      () => {
        this.clearPending()
        controller.updateFix(uid, { stage: 'applying' })
      }
    )

    if (outcome.status === 'not_confirmed') {
      this.options.log(`correctif IA non confirmé (${uid}) : aucune modification`)
      return
    }
    if (outcome.status === 'stale') {
      this.options.log(`correctif IA périmé pour ${uid} — ${outcome.reason}`)
      controller.updateFix(uid, { stage: 'stale', message: outcome.reason })
      return
    }
    if (outcome.status === 'failed') {
      this.options.log(
        `correctif IA non appliqué pour ${uid} — ${outcome.reason} ` +
          `(${outcome.restored ? 'fichier restauré' : 'restauration impossible'})`
      )
      controller.updateFix(uid, {
        stage: 'failed',
        message: outcome.reason,
        restored: outcome.restored,
      })
      return
    }

    this.options.log(
      `correctif IA appliqué : ${finding.file_path} lignes ${proposal.start_line}-${proposal.end_line}`
    )

    // Nouvelle analyse déterministe. Aucune décision « corrigé » n'est
    // enregistrée : c'est le résultat de cette analyse qui fait foi.
    controller.updateFix(uid, { stage: 'rescanning' })
    const verification = await this.verify(finding, document)
    this.options.log(`vérification après correctif ${uid} : ${verification}`)
    controller.updateFix(uid, { stage: 'done', verification })
  }

  private async verify(finding: CodeFinding, document: vscode.TextDocument): Promise<Verification> {
    try {
      if (isProjectFinding(finding)) {
        const outcome = await this.options.rescanProjectFile(finding.file_path)
        if (outcome === undefined) {
          await this.options.fullSecurityScan()
        } else if (outcome.touched && !outcome.submitted) {
          // Le moteur a vu un changement que le backend n'a pas reçu : la
          // vue montre encore l'ancien état, elle ne prouve rien.
          return 'unverified'
        }
      } else {
        await this.options.rescanCodeDocument(document)
      }
    } catch (error) {
      this.options.log(
        `nouvelle analyse impossible après correctif — ${
          error instanceof Error ? error.message : String(error)
        }`
      )
      return 'unverified'
    }

    return stillDetected(finding, this.options.store.all()) ? 'still_present' : 'resolved'
  }

  private clearPending(): void {
    if (this.pending) {
      this.previews.delete(this.pending.previewUri.toString())
    }
    this.pending = undefined
  }
}
