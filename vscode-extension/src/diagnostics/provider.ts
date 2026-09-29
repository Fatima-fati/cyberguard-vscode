/**
 * Affichage des findings dans l'éditeur, via la couche Diagnostics.
 *
 * Le contenu affiché vient intégralement du backend : titre, explication,
 * conséquences et recommandations sont déjà rédigés en français par
 * `app/code/rules.py`. L'extension ne réécrit rien, elle met en forme.
 */

import * as vscode from 'vscode'

import type { CodeFinding, SeverityCounts } from '../api/backendClient'
import { FR } from '../i18n/fr'
import { findingRange } from './findingRange'
import { buildDiagnosticMessage } from './hoverMessage'
import { toDiagnosticSeverity } from './severityMap'

/**
 * Registre des findings, en plus de leur affichage.
 *
 * Le Quick Fix et la fenêtre de détail partent d'un diagnostic ou d'un
 * identifiant : il faut donc pouvoir remonter au finding complet. Ce
 * registre vit uniquement en mémoire — rien n'est écrit dans
 * `globalState` ni `workspaceState`, et il ne contient jamais le contenu
 * du fichier, seulement les extraits déjà expurgés par le backend.
 */
export class DiagnosticsProvider implements vscode.Disposable {
  private readonly collection: vscode.DiagnosticCollection
  private readonly byUri = new Map<string, CodeFinding[]>()
  /**
   * Empreinte du contenu analysé, par document.
   *
   * C'est la provenance des findings affichés : elle permet de savoir, au
   * moment d'appliquer un correctif, si le fichier est toujours celui qui
   * a été analysé. Le contenu lui-même n'est jamais conservé.
   */
  private readonly analyzedHashes = new Map<string, string>()

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection('wazuhSecurity')
  }

  /** Remplace les diagnostics du document par ceux du dernier scan. */
  publish(
    document: vscode.TextDocument,
    findings: CodeFinding[],
    analyzedHash?: string
  ): void {
    const key = document.uri.toString()
    this.byUri.set(key, findings)

    if (analyzedHash) {
      this.analyzedHashes.set(key, analyzedHash)
    } else {
      // Sans empreinte connue, mieux vaut aucune valeur qu'une valeur
      // périmée : le contrôle de dérive saura qu'il ne peut pas conclure.
      this.analyzedHashes.delete(key)
    }

    this.render(document, findings)
  }

  /** Empreinte du contenu qui a produit les findings de ce document. */
  analyzedHash(uri: vscode.Uri): string | undefined {
    return this.analyzedHashes.get(uri.toString())
  }

  /**
   * Remplace un finding par sa version enrichie (arrivée par SSE).
   *
   * Retourne les compteurs à jour, ou `undefined` si le finding n'est pas
   * connu de ce document — un résultat qui ne correspond à rien d'affiché
   * n'est jamais inséré de force.
   */
  upsert(document: vscode.TextDocument, updated: CodeFinding): SeverityCounts | undefined {
    const key = document.uri.toString()
    const current = this.byUri.get(key)
    if (!current) {
      return undefined
    }

    const index = current.findIndex(
      (finding) => finding.finding_uid === updated.finding_uid
    )
    if (index === -1) {
      return undefined
    }

    current[index] = updated
    this.byUri.set(key, current)
    this.render(document, current)
    return this.counts(document.uri)
  }

  /** Findings connus pour ce document. */
  findingsFor(uri: vscode.Uri): CodeFinding[] {
    return this.byUri.get(uri.toString()) ?? []
  }

  /** Findings ouverts dont la ligne croise la sélection. */
  findingsAt(uri: vscode.Uri, range: vscode.Range): CodeFinding[] {
    return this.findingsFor(uri).filter((finding) => {
      if (finding.status !== 'open') {
        return false
      }
      const start = finding.location.line_start - 1
      const end = finding.location.line_end - 1
      return range.start.line <= end && range.end.line >= start
    })
  }

  /** Retrouve un finding par son identifiant, tous documents confondus. */
  findByUid(uid: string): { uri: vscode.Uri; finding: CodeFinding } | undefined {
    for (const [key, findings] of this.byUri) {
      const finding = findings.find((item) => item.finding_uid === uid)
      if (finding) {
        return { uri: vscode.Uri.parse(key), finding }
      }
    }
    return undefined
  }

  /** Répartition par sévérité des findings encore ouverts. */
  counts(uri: vscode.Uri): SeverityCounts {
    const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 }

    for (const finding of this.findingsFor(uri)) {
      if (finding.status !== 'open') {
        continue
      }
      if (finding.severity === 'CRITICAL') {
        counts.critical += 1
      } else if (finding.severity === 'HIGH') {
        counts.high += 1
      } else if (finding.severity === 'MEDIUM') {
        counts.medium += 1
      } else {
        counts.low += 1
      }
    }

    return counts
  }

  /** Efface les diagnostics d'un document (fermeture, fichier exclu). */
  clear(uri: vscode.Uri): void {
    this.collection.delete(uri)
    this.byUri.delete(uri.toString())
    this.analyzedHashes.delete(uri.toString())
  }

  /**
   * Efface tous les diagnostics (commande « Clear Findings »).
   *
   * L'affichage seul est vidé : le backend conserve son historique, et
   * une nouvelle analyse le fait réapparaître.
   */
  clearAll(): void {
    this.collection.clear()
    this.byUri.clear()
    this.analyzedHashes.clear()
  }

  dispose(): void {
    this.collection.dispose()
    this.byUri.clear()
    this.analyzedHashes.clear()
  }

  private render(document: vscode.TextDocument, findings: CodeFinding[]): void {
    const diagnostics = findings
      .filter((finding) => finding.status === 'open')
      .map((finding) => this.toDiagnostic(document, finding))

    this.collection.set(document.uri, diagnostics)
  }

  // ---------------- Interne ----------------

  private toDiagnostic(
    document: vscode.TextDocument,
    finding: CodeFinding
  ): vscode.Diagnostic {
    const diagnostic = new vscode.Diagnostic(
      // Même calcul que le positionnement du curseur depuis la vue
      // « Security » : les deux doivent désigner exactement la même zone.
      findingRange(document, finding),
      buildDiagnosticMessage(finding),
      toDiagnosticSeverity(finding.severity)
    )

    diagnostic.source = FR.diagnosticSource
    // `code` sert d'ancre visuelle ; l'identifiant du finding voyage dans
    // les données attachées, exploitées par le fournisseur de Quick Fix.
    ;(diagnostic as vscode.Diagnostic & { findingUid?: string }).findingUid =
      finding.finding_uid

    // Le code affiché renvoie vers la fiche CWE quand elle existe : le
    // développeur peut approfondir sans quitter l'éditeur.
    const cweId = finding.cwe?.match(/CWE-(\d+)/)?.[1]
    diagnostic.code = cweId
      ? {
          value: `${finding.rule_id} · ${finding.cwe}`,
          target: vscode.Uri.parse(
            `https://cwe.mitre.org/data/definitions/${cweId}.html`
          ),
        }
      : finding.rule_id

    return diagnostic
  }

}
