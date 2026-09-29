/**
 * HTML de la fenêtre de l'assistant IA de sécurité (phase 6).
 *
 * Séparé de `aiPanel.ts` pour la même raison que `detailHtml.ts` l'est de
 * `detailPanel.ts` : c'est ici que se joue la sécurité de la page, et ces
 * règles se vérifient sans ouvrir VS Code.
 *
 * Trois règles d'affichage, tenues partout
 * ----------------------------------------
 *
 * 1. **Tout texte d'IA porte la pastille « Généré par IA »** et la mise en
 *    garde du backend. Il n'existe aucun chemin de rendu d'une réponse sans
 *    elles.
 * 2. **La gravité affichée est celle du moteur** (`deterministic_severity`),
 *    présentée dans un encadré séparé du texte de l'IA. Aucun champ d'une
 *    réponse d'IA n'alimente une pastille de gravité.
 * 3. **Tout contenu dynamique est échappé.** Une réponse de modèle est du
 *    texte arbitraire, et elle peut recopier une preuve venue du dépôt
 *    analysé : elle n'est jamais interprétée comme du HTML.
 *
 * CSP : `default-src 'none'`, style et script par nonce uniquement, aucune
 * ressource externe, aucun `connect-src` — la page ne parle à personne
 * d'autre qu'à l'extension, par `postMessage`.
 *
 * Aucune dépendance à `vscode`.
 */

import type { AiPanelModel, ChatEntry } from '../ai/securityAiController'
import type { SecurityFindingAiAnalysis, SecurityFindingsAiSummary } from '../ai/aiTypes'
import { FR } from '../i18n/fr'
import { escapeHtml, severityClassOf } from './detailHtml'

const A = FR.assistant

function text(value: string | null | undefined): string {
  return escapeHtml((value ?? '').trim())
}

/** Section affichée seulement quand elle a un contenu : rien n'est comblé. */
function section(title: string, body: string | null | undefined): string {
  const content = (body ?? '').trim()
  return content ? `<h3>${escapeHtml(title)}</h3><p>${escapeHtml(content)}</p>` : ''
}

function listSection(title: string, items: readonly string[] | null | undefined): string {
  const entries = (items ?? []).filter((item) => typeof item === 'string' && item.trim())
  if (entries.length === 0) {
    return ''
  }
  return (
    `<h3>${escapeHtml(title)}</h3><ul>` +
    entries.map((item) => `<li>${escapeHtml(item.trim())}</li>`).join('') +
    '</ul>'
  )
}

function orderedSection(title: string, items: readonly string[] | null | undefined): string {
  const entries = (items ?? []).filter((item) => typeof item === 'string' && item.trim())
  if (entries.length === 0) {
    return ''
  }
  return (
    `<h3>${escapeHtml(title)}</h3><ol>` +
    entries.map((item) => `<li>${escapeHtml(item.trim())}</li>`).join('') +
    '</ol>'
  )
}

/** Pastille et mise en garde : l'en-tête obligatoire de tout texte d'IA. */
function aiHeader(disclaimer: string): string {
  return (
    `<div class="ai-mark"><span class="badge ai">${escapeHtml(A.badge)}</span>` +
    `<span class="disclaimer">${text(disclaimer || A.unavailableDefault)}</span></div>`
  )
}

function insufficient(flag: boolean, missing: readonly string[]): string {
  if (!flag) {
    return ''
  }
  return (
    `<div class="notice"><strong>${escapeHtml(A.insufficientTitle)}</strong>` +
    `<p>${escapeHtml(A.insufficientText)}</p>` +
    listSection(A.missingInformation, missing) +
    '</div>'
  )
}

/**
 * Encadré du finding déterministe.
 *
 * Visuellement séparé du texte de l'IA : c'est la seule partie de la page
 * qui fasse foi, et le lecteur doit pouvoir la distinguer d'un coup d'œil.
 */
function deterministicBox(analysis: SecurityFindingAiAnalysis): string {
  const severityClass = severityClassOf(analysis.deterministic_severity)
  const location = analysis.file
    ? `${text(analysis.file)}${analysis.line ? `:${escapeHtml(String(analysis.line))}` : ''}`
    : ''

  return (
    '<div class="finding">' +
    `<h2>${escapeHtml(A.finding)}</h2>` +
    `<p class="title">${text(analysis.deterministic_title)}</p>` +
    '<div class="badges">' +
    `<span class="badge ${severityClass}">${text(analysis.deterministic_severity)}</span>` +
    `<span class="badge">${text(analysis.category)}</span>` +
    `<span class="badge">${text(analysis.detection_engine)}</span>` +
    '</div>' +
    (location ? `<p class="meta">${location}</p>` : '') +
    `<p class="meta">${escapeHtml(A.deterministicNote)}</p>` +
    section(A.engineRemediation, analysis.deterministic_remediation) +
    '</div>'
  )
}

function analysisBody(analysis: SecurityFindingAiAnalysis, disclaimer: string): string {
  const percent = Math.round(Math.max(0, Math.min(1, Number(analysis.confidence) || 0)) * 100)
  const example = (analysis.secure_example ?? '').trim()

  return (
    deterministicBox(analysis) +
    '<div class="ai">' +
    aiHeader(analysis.disclaimer || disclaimer) +
    insufficient(analysis.insufficient_context, analysis.missing_information) +
    section(A.developerSummary, analysis.developer_summary) +
    section(A.explanation, analysis.explanation) +
    section(A.whyItMatters, analysis.why_it_matters) +
    section(A.projectImpact, analysis.project_impact) +
    section(A.evidenceInterpretation, analysis.evidence_interpretation) +
    section(A.recommendation, analysis.recommendation) +
    orderedSection(A.steps, analysis.remediation_steps) +
    (example
      ? `<h3>${escapeHtml(A.secureExample)}${
          analysis.secure_example_language
            ? ` <span class="meta">(${text(analysis.secure_example_language)})</span>`
            : ''
        }</h3><pre>${escapeHtml(example)}</pre>`
      : '') +
    listSection(A.relatedConcepts, analysis.related_concepts) +
    `<p class="meta">${escapeHtml(
      A.coverage(analysis.project_context_available, analysis.related_findings_considered)
    )}</p>` +
    `<p class="meta">${escapeHtml(A.aiConfidence(percent))}` +
    `${analysis.cached ? ` · ${escapeHtml(A.cached)}` : ''}</p>` +
    `<p class="meta">${escapeHtml(A.modelLine(analysis.model, analysis.analyzed_at))}</p>` +
    '</div>'
  )
}

function summaryBody(summary: SecurityFindingsAiSummary, disclaimer: string): string {
  return (
    '<div class="ai">' +
    `<h2>${escapeHtml(A.summaryTitle)}</h2>` +
    aiHeader(summary.disclaimer || disclaimer) +
    `<p class="meta">${escapeHtml(
      A.summaryCoverage(summary.findings_considered, summary.findings_available, summary.truncated)
    )}</p>` +
    insufficient(summary.insufficient_context, summary.missing_information) +
    `<p>${text(summary.summary)}</p>` +
    listSection(A.themes, summary.themes) +
    listSection(A.relationships, summary.relationships) +
    orderedSection(A.priorityOrder, summary.priority_order) +
    `<p class="meta">${escapeHtml(A.modelLine(summary.model, summary.analyzed_at))}</p>` +
    '</div>'
  )
}

function chatEntry(entry: ChatEntry, disclaimer: string): string {
  const question =
    `<div class="turn user"><strong>${escapeHtml(A.chatYou)}</strong>` +
    `<p>${text(entry.question)}</p>` +
    (entry.redacted ? `<p class="meta">${escapeHtml(A.chatRedacted)}</p>` : '') +
    '</div>'

  if (entry.pending) {
    return `${question}<div class="turn pending">${escapeHtml(A.chatPending)}</div>`
  }
  if (entry.error || !entry.response) {
    return `${question}<div class="turn error">${text(entry.error || A.errorFor(0))}</div>`
  }

  const response = entry.response
  return (
    question +
    '<div class="turn assistant">' +
    `<strong>${escapeHtml(A.chatAssistant)}</strong>` +
    aiHeader(response.disclaimer || disclaimer) +
    insufficient(response.insufficient_context, response.missing_information) +
    `<p>${text(response.answer)}</p>` +
    listSection(A.relatedConcepts, response.related_concepts) +
    `<p class="meta">${escapeHtml(
      A.chatCoverage(response.findings_considered, response.findings_available, response.truncated)
    )}</p>` +
    '</div>'
  )
}

function chatBlock(model: AiPanelModel): string {
  const history = model.chat.map((entry) => chatEntry(entry, model.disclaimer)).join('')
  const pending = model.chat.some((entry) => entry.pending)

  const form = model.chatAvailable
    ? '<form id="chat">' +
      `<textarea id="question" rows="3" maxlength="1000" placeholder="${escapeHtml(
        A.chatPlaceholder
      )}"${pending ? ' disabled' : ''}></textarea>` +
      `<button type="submit" id="send"${pending ? ' disabled' : ''}>${escapeHtml(
        A.chatSend
      )}</button>` +
      '</form>'
    : `<p class="absent">${escapeHtml(A.chatUnavailable)}</p>`

  return `<h2>${escapeHtml(A.chatTitle)}</h2><div class="chat">${history}</div>${form}`
}

function statusBlock(model: AiPanelModel): string {
  switch (model.status) {
    case 'loading':
      return `<p class="loading">${escapeHtml(A.loading)}</p>`
    case 'unavailable':
      return (
        '<div class="notice">' +
        `<strong>${escapeHtml(A.unavailableTitle)}</strong>` +
        `<p>${text(model.message || A.unavailableDefault)}</p>` +
        `<p class="meta">${escapeHtml(A.scanningUnaffected)}</p>` +
        '</div>'
      )
    case 'error':
      return (
        '<div class="notice error">' +
        `<strong>${escapeHtml(A.errorTitle)}</strong>` +
        `<p>${text(model.message)}</p>` +
        `<p class="meta">${escapeHtml(A.scanningUnaffected)}</p>` +
        '</div>'
      )
    default:
      return ''
  }
}

/**
 * Correctif assisté (phase 7).
 *
 * Le bouton « Appliquer » n'existe qu'à l'étape `proposed`, c'est-à-dire
 * pour une proposition que l'extension a elle-même validée. Il n'écrit
 * rien : il ouvre la confirmation native de l'éditeur. Le code actuel
 * affiché est la version **expurgée** de la plage — un secret n'apparaît
 * jamais dans cette page.
 */
function fixBody(model: AiPanelModel): string {
  const fix = model.fix
  if (!fix) {
    return ''
  }
  const R = FR.remediation
  const proposal = fix.proposal

  const steps = listSection(R.manualSteps, fix.manualSteps ?? proposal?.manual_steps)

  if (fix.stage === 'loading') {
    return `<p class="loading">${escapeHtml(R.loading)}</p>`
  }

  if (fix.stage === 'refused' || fix.stage === 'rejected') {
    return (
      `<div class="notice${fix.stage === 'rejected' ? ' error' : ''}">` +
      `<strong>${escapeHtml(R.manualRequired)}</strong>` +
      `<p>${text(fix.message)}</p>` +
      `<p class="meta">${escapeHtml(R.notApplied)}</p>` +
      '</div>' +
      section(R.explanation, fix.explanation) +
      steps
    )
  }

  if (!proposal) {
    return fix.message ? `<div class="notice error"><p>${text(fix.message)}</p></div>` : ''
  }

  const location = R.affected(proposal.file, proposal.start_line, proposal.end_line)
  const stageNotice = (() => {
    switch (fix.stage) {
      case 'applying':
        return `<p class="loading">${escapeHtml(R.applying)}</p>`
      case 'rescanning':
        return `<p class="loading">${escapeHtml(R.rescanning)}</p>`
      case 'cancelled':
        return `<div class="notice"><p>${escapeHtml(R.cancelled)}</p></div>`
      case 'stale':
        return (
          `<div class="notice error"><p>${text(fix.message)}</p>` +
          `<p class="meta">${escapeHtml(R.needFresh)}</p></div>`
        )
      case 'failed':
        return (
          `<div class="notice error"><strong>${escapeHtml(A.errorTitle)}</strong>` +
          `<p>${text(fix.message)}</p>` +
          `<p>${escapeHtml(fix.restored === false ? R.notRestored : R.restored)}</p></div>`
        )
      case 'done': {
        const verdict =
          fix.verification === 'resolved'
            ? R.resolved
            : fix.verification === 'still_present'
              ? R.stillPresent
              : R.unverified
        return (
          `<div class="notice${fix.verification === 'resolved' ? '' : ' error'}">` +
          `<strong>${escapeHtml(verdict)}</strong>` +
          `<p class="meta">${escapeHtml(R.noDecision)}</p></div>`
        )
      }
      default:
        return `<p class="meta">${escapeHtml(R.notApplied)}</p>`
    }
  })()

  const buttons =
    fix.stage === 'proposed'
      ? '<div class="actions">' +
        `<button id="applyFix">${escapeHtml(R.apply)}</button>` +
        `<button id="showFixDiff" class="secondary">${escapeHtml(R.showDiff)}</button>` +
        `<button id="cancelFix" class="secondary">${escapeHtml(R.cancel)}</button>` +
        '</div>'
      : ''

  return (
    '<div class="finding">' +
    `<h2>${escapeHtml(A.finding)}</h2>` +
    `<p class="title">${text(proposal.deterministic_title)}</p>` +
    '<div class="badges">' +
    `<span class="badge ${severityClassOf(proposal.deterministic_severity)}">${text(
      proposal.deterministic_severity
    )}</span>` +
    `<span class="badge">${text(proposal.category)}</span>` +
    '</div>' +
    `<p class="meta">${text(location)}</p>` +
    `<p class="meta">${escapeHtml(A.deterministicNote)}</p>` +
    '</div>' +
    '<div class="ai">' +
    aiHeader(proposal.disclaimer || model.disclaimer) +
    stageNotice +
    (fix.currentLines && fix.currentLines.length > 0
      ? `<h3>${escapeHtml(R.currentCode)}</h3><pre>${escapeHtml(fix.currentLines.join('\n'))}</pre>`
      : '') +
    `<h3>${escapeHtml(R.proposedCode)}</h3><pre>${escapeHtml(
      proposal.replacement_lines.join('\n')
    )}</pre>` +
    section(R.explanation, proposal.explanation) +
    section(R.reason, proposal.reason) +
    listSection(R.warnings, proposal.warnings) +
    steps +
    buttons +
    '</div>'
  )
}

function heading(model: AiPanelModel): string {
  switch (model.view.kind) {
    case 'analysis':
    case 'fix':
      return model.view.findingTitle || A.panelTitle
    case 'summary':
      return A.summaryTitle
    default:
      return A.chatTitle
  }
}

/** Page complète. `nonce` est régénéré par l'appelant à chaque rendu. */
export function buildAiPanelHtml(model: AiPanelModel, nonce: string): string {
  const content =
    model.status === 'ready' && model.view.kind === 'analysis' && model.analysis
      ? analysisBody(model.analysis, model.disclaimer)
      : model.status === 'ready' && model.view.kind === 'summary' && model.summary
        ? summaryBody(model.summary, model.disclaimer)
        : model.view.kind === 'fix'
          ? fixBody(model)
          : ''

  // Refaire l'analyse n'a pas de sens pour un correctif : une nouvelle
  // proposition se redemande depuis le signalement, sur le fichier actuel.
  const canRedo =
    model.view.kind !== 'chat' &&
    model.view.kind !== 'fix' &&
    (model.status === 'ready' || model.status === 'error')

  const actions =
    '<div class="actions">' +
    (canRedo
      ? `<button id="reanalyze" class="secondary">${escapeHtml(A.actionReanalyze)}</button>`
      : '') +
    (model.status !== 'unavailable'
      ? `<button id="summarize" class="secondary">${escapeHtml(A.actionSummarize)}</button>`
      : '') +
    '</div>'

  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; img-src 'none'; font-src 'none'; connect-src 'none';
               style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}';
               form-action 'none'; base-uri 'none'; frame-src 'none'; object-src 'none';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(A.panelTitle)}</title>
<style nonce="${nonce}">
  body { font-family: var(--vscode-font-family); font-size: 13px;
         color: var(--vscode-foreground); padding: 16px 20px; line-height: 1.55; }
  h1 { font-size: 17px; margin: 0 0 10px; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .05em;
       opacity: .75; margin: 18px 0 6px; }
  h3 { font-size: 13px; margin: 14px 0 4px; }
  p { margin: 4px 0; }
  ul, ol { margin: 4px 0 0; padding-left: 20px; }
  .badges { display: flex; flex-wrap: wrap; gap: 8px; margin: 6px 0; }
  .badge { padding: 2px 9px; border-radius: 999px; font-size: 11px;
           font-weight: 600; border: 1px solid currentColor; }
  .badge.ai { color: var(--vscode-charts-purple); }
  .critical, .high { color: var(--vscode-editorError-foreground); }
  .medium { color: var(--vscode-editorWarning-foreground); }
  .low { color: var(--vscode-editorInfo-foreground); }
  .finding { border-left: 3px solid var(--vscode-editorInfo-foreground);
             padding: 4px 12px; margin-bottom: 14px; }
  .finding .title { font-weight: 600; }
  .ai { border-left: 3px solid var(--vscode-charts-purple); padding: 4px 12px; }
  .ai-mark { display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
             margin: 4px 0 8px; }
  .disclaimer { font-size: 11px; opacity: .8; }
  .meta { opacity: .75; font-size: 12px; }
  .absent { opacity: .6; font-style: italic; }
  .loading { font-style: italic; opacity: .8; }
  .notice { border: 1px solid var(--vscode-editorWarning-foreground);
            border-radius: 4px; padding: 8px 12px; margin: 10px 0; }
  .notice.error { border-color: var(--vscode-editorError-foreground); }
  pre { background: var(--vscode-textCodeBlock-background); padding: 10px;
        border-radius: 4px; overflow-x: auto; white-space: pre-wrap;
        word-break: break-word; font-family: var(--vscode-editor-font-family); }
  .turn { margin: 8px 0; padding: 6px 10px; border-radius: 4px; }
  .turn.user { background: var(--vscode-editor-inactiveSelectionBackground); }
  .turn.pending { font-style: italic; opacity: .8; }
  .turn.error { color: var(--vscode-editorError-foreground); }
  form { display: flex; flex-direction: column; gap: 6px; margin-top: 10px; }
  textarea { font-family: inherit; font-size: 13px; resize: vertical;
             color: var(--vscode-input-foreground);
             background: var(--vscode-input-background);
             border: 1px solid var(--vscode-input-border, transparent); padding: 6px; }
  .actions { display: flex; gap: 8px; margin-top: 18px; flex-wrap: wrap; }
  button { font-family: inherit; font-size: 12px; padding: 6px 14px; border: none;
           border-radius: 3px; cursor: pointer; align-self: flex-start;
           background: var(--vscode-button-background);
           color: var(--vscode-button-foreground); }
  button.secondary { background: var(--vscode-button-secondaryBackground);
                     color: var(--vscode-button-secondaryForeground); }
  button:disabled { opacity: .5; cursor: default; }
</style>
</head>
<body>
  <h1>${text(heading(model))}</h1>
  ${statusBlock(model)}
  ${content}
  ${actions}
  ${model.status === 'unavailable' ? '' : chatBlock(model)}
<script nonce="${nonce}">
  // Aucun gestionnaire en ligne : la CSP l'interdirait, et un attribut
  // construit par concaténation serait un point d'injection. La page ne
  // fait que relayer trois intentions ; l'extension les valide.
  const api = acquireVsCodeApi()
  for (const action of ['reanalyze', 'summarize', 'applyFix', 'cancelFix', 'showFixDiff']) {
    const button = document.getElementById(action)
    if (button) {
      button.addEventListener('click', () => api.postMessage({ action }))
    }
  }
  const form = document.getElementById('chat')
  const field = document.getElementById('question')
  if (form && field) {
    form.addEventListener('submit', (event) => {
      event.preventDefault()
      const question = field.value.trim()
      if (question) {
        api.postMessage({ action: 'ask', question })
      }
    })
  }
</script>
</body>
</html>`
}
