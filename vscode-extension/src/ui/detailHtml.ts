/**
 * Construction du HTML de la fiche détaillée.
 *
 * Séparé de `detailPanel.ts` — qui n'a plus qu'à créer la webview et
 * relayer deux clics — parce que c'est ici que se joue la sécurité de la
 * page : l'échappement de contenus qui viennent du code de l'utilisateur,
 * et la CSP qui interdit tout le reste. Ces règles se vérifient sans
 * ouvrir VS Code.
 *
 * Aucune dépendance à `vscode`.
 */

import type { CodeFinding } from '../api/backendClient'
import { FR } from '../i18n/fr'

/** Échappement systématique : le contenu affiché n'est jamais du HTML. */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/** Paragraphe échappé, ou mention d'absence. Aucun contenu n'est inventé. */
function paragraph(value: string | null | undefined): string {
  const text = (value ?? '').trim()
  return text
    ? `<p>${escapeHtml(text)}</p>`
    : `<p class="absent">${FR.detail.unavailable}</p>`
}

/** Liste échappée, ou mention d'absence. */
function list(items: readonly string[] | null | undefined): string {
  const entries = (items ?? []).filter(
    (item) => typeof item === 'string' && item.trim()
  )
  if (entries.length === 0) {
    return `<p class="absent">${FR.detail.unavailable}</p>`
  }
  return `<ul>${entries
    .map((item) => `<li>${escapeHtml(item.trim())}</li>`)
    .join('')}</ul>`
}

/** Valeur en ligne, ou mention d'absence. */
function inline(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === '') {
    return `<span class="absent">${FR.detail.unavailable}</span>`
  }
  return escapeHtml(String(value))
}

/**
 * Page complète de la fiche.
 *
 * `nonce` est fourni par l'appelant, qui le régénère à chaque rendu : il
 * autorise le seul style et le seul script de la page, et rien d'autre.
 */
/**
 * Classe CSS de la pastille de gravité.
 *
 * Choisie dans une liste fermée, jamais dérivée du texte reçu : une
 * valeur inattendue placée dans un attribut `class` pourrait s'en
 * échapper et injecter d'autres attributs. Ici, seules quatre valeurs
 * sont possibles, et l'inconnu retombe sur la plus discrète.
 */
export function severityClassOf(severity: string): 'critical' | 'high' | 'medium' | 'low' {
  switch (severity) {
    case 'CRITICAL':
      return 'critical'
    case 'HIGH':
      return 'high'
    case 'MEDIUM':
      return 'medium'
    default:
      return 'low'
  }
}

export interface DetailHtmlOptions {
  /**
   * Afficher « Analyser avec l'IA » (phase 6). Faux par défaut : le bouton
   * n'apparaît que lorsque le backend annonce une action IA pour ce
   * finding. L'IA explique ; la fiche, elle, reste celle du moteur.
   */
  aiAvailable?: boolean
  /**
   * Afficher « Suggest Fix with AI » (phase 7). Le bouton ne modifie rien :
   * il demande une proposition, montrée ensuite avec un aperçu, et
   * appliquée seulement après confirmation.
   */
  aiFixAvailable?: boolean
}

export function buildDetailHtml(
  finding: CodeFinding,
  nonce: string,
  options: DetailHtmlOptions = {}
): string {
  const severityClass = severityClassOf(finding.severity)

  const factors =
    finding.risk_factors && finding.risk_factors.length > 0
      ? `<ul>${finding.risk_factors
          .map(
            (factor) =>
              `<li><strong>${escapeHtml(factor.name)}</strong>` +
              `${
                factor.weight
                  ? ` (${factor.weight > 0 ? '+' : ''}${escapeHtml(
                      String(factor.weight)
                    )})`
                  : ''
              }` +
              ` : ${escapeHtml(factor.detail)}</li>`
          )
          .join('')}</ul>`
      : `<p class="absent">${FR.detail.unavailable}</p>`

  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; img-src 'none'; font-src 'none'; connect-src 'none';
               style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';
               form-action 'none'; base-uri 'none'; frame-src 'none'; object-src 'none';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(FR.detail.title)}</title>
<style nonce="${nonce}">
  body { font-family: var(--vscode-font-family); font-size: 13px;
         color: var(--vscode-foreground); padding: 16px 20px; line-height: 1.55; }
  h1 { font-size: 17px; margin: 0 0 4px; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .05em;
       opacity: .75; margin: 20px 0 6px; }
  p { margin: 4px 0; }
  .badges { display: flex; flex-wrap: wrap; gap: 8px; margin: 10px 0 4px; }
  .badge { padding: 2px 9px; border-radius: 999px; font-size: 11px;
           font-weight: 600; border: 1px solid currentColor; }
  .critical { color: var(--vscode-editorError-foreground); }
  .high     { color: var(--vscode-editorError-foreground); }
  .medium   { color: var(--vscode-editorWarning-foreground); }
  .low      { color: var(--vscode-editorInfo-foreground); }
  .meta { opacity: .8; font-size: 12px; margin: 2px 0; }
  .absent { opacity: .6; font-style: italic; }
  pre { background: var(--vscode-textCodeBlock-background); padding: 10px;
        border-radius: 4px; overflow-x: auto; white-space: pre-wrap;
        word-break: break-word; font-family: var(--vscode-editor-font-family); }
  ul { margin: 4px 0 0; padding-left: 20px; }
  li { margin: 3px 0; }
  .actions { display: flex; gap: 8px; margin-top: 24px; flex-wrap: wrap; }
  button { font-family: inherit; font-size: 12px; padding: 6px 14px;
           border: none; border-radius: 3px; cursor: pointer;
           background: var(--vscode-button-background);
           color: var(--vscode-button-foreground); }
  button.secondary { background: var(--vscode-button-secondaryBackground);
                     color: var(--vscode-button-secondaryForeground); }
  button:hover { background: var(--vscode-button-hoverBackground); }
</style>
</head>
<body>
  <h1>${inline(finding.title || finding.category_label)}</h1>

  <div class="badges">
    <span class="badge ${severityClass}">${inline(
      finding.severity_label || finding.severity
    )}</span>
    <span class="badge">${inline(finding.category_label || finding.category)}</span>
    <span class="badge">${inline(finding.rule_id)}</span>
  </div>

  <p class="meta">${FR.detail.severity} : ${inline(
    finding.severity_label || finding.severity
  )}</p>
  <p class="meta">${FR.detail.category} : ${inline(
    finding.category_label || finding.category
  )}</p>
  <p class="meta">CWE : ${inline(finding.cwe)} · OWASP : ${inline(finding.owasp)}</p>
  <p class="meta">${FR.detail.location} : ${inline(finding.file_path)}, ligne ${inline(
    finding.location?.line_start
  )}</p>
  <p class="meta">${FR.detail.score} : ${inline(finding.risk_score)}/100 (${inline(
    finding.risk_band
  )}) · ${FR.detail.confidence} : ${
    typeof finding.confidence === 'number'
      ? `${Math.round(finding.confidence * 100)} %`
      : `<span class="absent">${FR.detail.unavailable}</span>`
  }</p>
  <p class="meta">${FR.detail.detectedBy} : ${inline(
    finding.source_label || finding.source
  )}</p>
  <p class="meta">${FR.detail.status} : ${inline(
    finding.status_label || finding.status
  )}</p>

  <h2>${FR.detail.snippet}</h2>
  ${
    finding.location?.snippet
      ? `<pre>${escapeHtml(finding.location.snippet)}</pre>`
      : `<p class="absent">${FR.detail.unavailable}</p>`
  }

  <h2>${FR.detail.explanation}</h2>
  ${paragraph(finding.explanation)}

  <h2>${FR.diagnostic.why}</h2>
  ${paragraph(finding.why_dangerous)}

  <h2>${FR.diagnostic.impact}</h2>
  ${list(finding.potential_impact)}

  <h2>${FR.diagnostic.recommendation}</h2>
  ${list(finding.recommendations)}

  <h2>${FR.detail.riskFactors}</h2>
  ${factors}

  <h2>${FR.detail.noFix}</h2>
  <p>${
    finding.fix_available
      ? escapeHtml(finding.fix_summary || FR.detail.fixAvailable)
      : FR.detail.fixUnavailable
  }</p>

  <div class="actions">
    ${
      finding.fix_available
        ? `<button id="fix">${escapeHtml(FR.detail.actionFix)}</button>`
        : ''
    }
    <button id="dismiss" class="secondary">${escapeHtml(
      FR.detail.actionDismiss
    )}</button>
    ${
      options.aiAvailable
        ? `<button id="ai" class="secondary">${escapeHtml(FR.notify.analyzeWithAi)}</button>`
        : ''
    }
    ${
      options.aiFixAvailable && finding.status === 'open'
        ? `<button id="aiFix" class="secondary">${escapeHtml(FR.remediation.suggestFix)}</button>`
        : ''
    }
  </div>

<script nonce="${nonce}">
  // Aucun gestionnaire en ligne : la CSP l'interdirait, et un attribut
  // onclick construit par concaténation serait un point d'injection.
  const api = acquireVsCodeApi()
  for (const action of ['fix', 'dismiss', 'ai', 'aiFix']) {
    const button = document.getElementById(action)
    if (button) {
      button.addEventListener('click', () => api.postMessage({ action }))
    }
  }
</script>
</body>
</html>`
}
