/**
 * Findings de sécurité projet dans le panneau « Problems ».
 *
 * Collection distincte de celle de `DiagnosticsProvider`, et la séparation
 * porte une raison technique précise : celle-là publie pour un
 * `TextDocument` **ouvert**, parce qu'elle a besoin du texte de la ligne
 * pour calculer une plage de soulignement exacte. Un secret repéré pendant
 * le balayage du projet se trouve, lui, presque toujours dans un fichier
 * que personne n'a ouvert.
 *
 * Cette collection publie donc par URI, sans document : la plage couvre la
 * ligne entière. VS Code accepte des diagnostics pour un fichier fermé et
 * les affiche dans « Problems » ; ils s'ancrent au bon endroit dès que le
 * fichier est ouvert.
 *
 * Ce qui est affiché — et ce qui ne peut pas l'être
 * -------------------------------------------------
 *
 * Le message reprend le titre, la recommandation et la **preuve
 * expurgée**. L'extrait réel du fichier n'est pas disponible : il n'a
 * jamais quitté le moteur de détection. C'est une limite voulue, pas un
 * manque — afficher la valeur d'un secret dans le panneau « Problems » la
 * rendrait visible en partage d'écran et en capture.
 */

import * as vscode from 'vscode'

import { FR } from '../i18n/fr'
import type { SecurityFinding } from '../security/securityTypes'
import { levelFor } from './severityLevels'

/** Longueur maximale d'une ligne de message. Au-delà, « Problems » tronque. */
const MAX_MESSAGE_LENGTH = 400

export class ProjectDiagnostics implements vscode.Disposable {
  private readonly collection: vscode.DiagnosticCollection
  private readonly workspaceRoot: () => string | undefined

  constructor(workspaceRoot: () => string | undefined) {
    // Nom distinct de `wazuhSecurity` : l'utilisateur peut filtrer les
    // deux familles séparément dans « Problems ».
    this.collection = vscode.languages.createDiagnosticCollection(
      'wazuhSecurity.project'
    )
    this.workspaceRoot = workspaceRoot
  }

  /**
   * Remplace l'intégralité des diagnostics de sécurité projet.
   *
   * Remplacement global, comme pour le registre : un balayage couvre tout
   * le dossier d'un coup, et un secret corrigé doit disparaître même si
   * son fichier n'apparaît plus dans le nouveau lot.
   */
  publish(findings: readonly SecurityFinding[]): void {
    this.collection.clear()

    const root = this.workspaceRoot()
    if (!root) {
      // Sans dossier ouvert, un chemin relatif ne désigne aucun fichier.
      // Les findings restent visibles dans la vue « Security ».
      return
    }

    const byFile = new Map<string, vscode.Diagnostic[]>()

    for (const finding of findings) {
      if (!finding.file || finding.status !== 'open') {
        continue
      }
      // Une dépendance vulnérable pointe son manifeste sans numéro de
      // ligne : la souligner ligne 1 désignerait une ligne au hasard.
      // Elle reste dans la vue « Security », où elle a du sens.
      if (finding.line_start <= 0) {
        continue
      }

      const bucket = byFile.get(finding.file) ?? []
      bucket.push(this.toDiagnostic(finding))
      byFile.set(finding.file, bucket)
    }

    for (const [relativePath, diagnostics] of byFile) {
      const uri = vscode.Uri.joinPath(vscode.Uri.file(root), relativePath)
      this.collection.set(uri, diagnostics)
    }
  }

  /** Vide le panneau. Le backend, lui, conserve son historique. */
  clear(): void {
    this.collection.clear()
  }

  dispose(): void {
    this.collection.dispose()
  }

  // ---------------- Interne ----------------

  private toDiagnostic(finding: SecurityFinding): vscode.Diagnostic {
    const line = Math.max(0, finding.line_start - 1)
    const endLine = Math.max(line, finding.line_end - 1)

    // `Number.MAX_SAFE_INTEGER` en colonne de fin : VS Code borne la plage
    // au contenu réel de la ligne, sans qu'on ait besoin du document.
    const range = new vscode.Range(line, 0, endLine, Number.MAX_SAFE_INTEGER)

    const diagnostic = new vscode.Diagnostic(
      range,
      this.message(finding),
      vscode.DiagnosticSeverity[levelFor(finding.severity)]
    )

    diagnostic.source = FR.diagnosticSource
    diagnostic.code = finding.detection_engine || finding.category
    return diagnostic
  }

  /**
   * Message affiché dans « Problems ».
   *
   * La confiance y figure toujours : c'est elle qui dit à l'utilisateur
   * s'il regarde une certitude ou une piste, et l'omettre transformerait
   * une heuristique en verdict.
   */
  private message(finding: SecurityFinding): string {
    const lines = [
      finding.title,
      `${FR.detail.confidence} : ${finding.confidence_label}`,
    ]

    if (finding.evidence) {
      lines.push(finding.evidence)
    }
    if (finding.remediation) {
      lines.push(`${FR.diagnostic.recommendation} : ${finding.remediation}`)
    }
    lines.push(`${FR.diagnostic.detectedBy} : ${finding.detection_engine}`)

    return lines.join('\n').slice(0, MAX_MESSAGE_LENGTH)
  }
}
