/**
 * Remédiation assistée, cœur sans éditeur (phase 7).
 *
 *     finding → éligibilité → extrait expurgé → proposition du backend
 *             → VALIDATION → aperçu → confirmation → application bornée
 *             → nouvelle analyse déterministe → vérification
 *
 * Ce module contient tout ce qui **décide** : quel finding peut recevoir
 * un correctif, ce qui part vers le backend, si une proposition est sûre,
 * comment appliquer sans jamais laisser un fichier à moitié modifié, et
 * comment lire le résultat de la nouvelle analyse. Il ne connaît ni
 * `vscode` ni le disque : le document est une interface injectée
 * (`EditableDocument`), ce qui permet d'éprouver l'application et le
 * retour arrière en Node pur.
 *
 * Ce que ce module ne fait jamais
 * -------------------------------
 *
 * - **écrire sans confirmation.** `applyBoundedFix` n'est appelée qu'après
 *   la fenêtre modale de l'éditeur ; aucune fonction ici n'écrit à la
 *   réception d'une réponse ;
 * - **déclarer un finding corrigé.** Aucune décision n'est enregistrée :
 *   c'est la nouvelle analyse des moteurs déterministes qui dit si le
 *   problème a disparu (`stillDetected`) ;
 * - **toucher un fichier protégé** : `.env`, clés privées, certificats,
 *   fichiers d'identifiants, verrous de dépendances.
 */

import * as path from 'node:path'

import type { CodeFinding } from '../api/backendClient'
import { contentHash } from '../analysis/contentHash'
import type { SecurityFixProposal, SecurityFixRequest } from '../ai/aiTypes'
import { redactFreeText } from '../ai/aiRedaction'
import { FR } from '../i18n/fr'
import { isNeverRead } from '../project/projectDiscovery'
import { isProjectFinding } from '../security/findingAdapter'
import { manifestKind } from '../security/dependencyInventory'
import { MASK } from '../security/redaction'
import { scanForSecrets } from '../security/secretScanner'

/** Lignes de contexte de part et d'autre de la ligne visée. */
export const FIX_CONTEXT_LINES = 8
/** Plage maximale remplacée, alignée sur le défaut du backend. */
export const MAX_RANGE_LINES = 10
/** Lignes maximales du remplacement, alignées sur le défaut du backend. */
export const MAX_REPLACEMENT_LINES = 20
/** Longueur maximale d'une ligne transmise ou écrite. */
export const MAX_LINE_LENGTH = 500

const F = FR.remediation

// --------------------------------------------------------------------------
// Éligibilité
// --------------------------------------------------------------------------

/** Certificats et fichiers de clés : jamais modifiés par un correctif. */
const PROTECTED_SUFFIXES = ['.crt', '.cer', '.der', '.csr', '.p7b', '.p7c', '.p8', '.gpg', '.kdbx']

export type Eligibility = { ok: true } | { ok: false; reason: string }

/** Le fichier est-il de ceux qu'aucun correctif ne touche ? */
export function isProtectedPath(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/')
  if (isNeverRead(normalized)) {
    return true
  }
  const lowered = normalized.toLowerCase()
  return PROTECTED_SUFFIXES.some((suffix) => lowered.endsWith(suffix))
}

/** Fichier de verrouillage : régénéré par un gestionnaire, jamais édité. */
export function isLockfile(relativePath: string): boolean {
  const name = path.posix.basename(relativePath.replace(/\\/g, '/')).toLowerCase()
  return manifestKind(name)?.source === 'lockfile'
}

export function isDependencyFinding(finding: CodeFinding): boolean {
  return isProjectFinding(finding) && finding.category === 'vulnerable_dependency'
}

/** Nom du paquet d'un finding de dépendance : premier mot du titre. */
export function dependencyPackage(finding: CodeFinding): string {
  return (finding.title ?? '').split(' ', 1)[0]?.trim() ?? ''
}

/**
 * Ce finding peut-il recevoir un correctif assisté ?
 *
 * Appelée **avant** d'ouvrir le fichier : un `.env` n'est pas lu pour
 * découvrir ensuite qu'on ne le modifiera pas.
 */
export function fixEligibility(finding: CodeFinding): Eligibility {
  if (finding.status !== 'open') {
    return { ok: false, reason: F.notOpen }
  }
  if (!finding.file_path) {
    return { ok: false, reason: F.noFile }
  }
  if (isProtectedPath(finding.file_path)) {
    return { ok: false, reason: F.protectedFile(finding.file_path) }
  }
  if (isDependencyFinding(finding) && isLockfile(finding.file_path)) {
    return { ok: false, reason: F.lockfile(finding.file_path) }
  }
  if (isProjectFinding(finding) && finding.scan_uid === 'project:GIT') {
    return { ok: false, reason: F.unsupported }
  }
  return { ok: true }
}

// --------------------------------------------------------------------------
// Extrait envoyé au backend
// --------------------------------------------------------------------------

export interface SplitText {
  lines: string[]
  eol: '\n' | '\r\n'
}

/** Découpe en conservant la fin de ligne du fichier. */
export function splitLines(text: string): SplitText {
  return { lines: text.split(/\r?\n/), eol: text.includes('\r\n') ? '\r\n' : '\n' }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Ligne sur laquelle porte le correctif, numérotée à partir de 1.
 *
 * Un finding localisé porte sa ligne. Une dépendance vulnérable, non : le
 * moteur la rattache au manifeste. La ligne de déclaration est alors
 * cherchée par le nom du paquet — déterministe, et revérifiée par le
 * backend.
 */
export function locateTargetLine(finding: CodeFinding, lines: readonly string[]): number | undefined {
  if (isDependencyFinding(finding)) {
    const name = dependencyPackage(finding)
    if (!name) {
      return undefined
    }
    const pattern = new RegExp(
      `(?<![A-Za-z0-9_.\\-])${escapeRegExp(name)}(?![A-Za-z0-9_\\-])`,
      'i'
    )
    const index = lines.findIndex((line) => pattern.test(line))
    return index >= 0 ? index + 1 : undefined
  }

  const line = finding.location?.line_start ?? 0
  return line >= 1 && line <= lines.length ? line : undefined
}

export type BuiltRequest =
  | { ok: true; request: SecurityFixRequest; targetLine: number }
  | { ok: false; reason: string }

/**
 * Construit la demande : un extrait borné, **expurgé ligne à ligne**.
 *
 * Jamais le fichier entier. L'empreinte du fichier, elle, est calculée
 * sur le texte réel : c'est elle qui sera comparée avant d'écrire.
 */
export function buildFixRequest(
  finding: CodeFinding,
  text: string,
  relativePath: string,
  language: string,
  contextLines = FIX_CONTEXT_LINES
): BuiltRequest {
  const { lines } = splitLines(text)
  const targetLine = locateTargetLine(finding, lines)
  if (targetLine === undefined) {
    return {
      ok: false,
      reason: isDependencyFinding(finding) ? F.dependencyNotFound : F.lineGone,
    }
  }

  const start = Math.max(1, targetLine - contextLines)
  const end = Math.min(lines.length, targetLine + contextLines)
  const excerpt = lines
    .slice(start - 1, end)
    .map((line) => redactFreeText(line, MAX_LINE_LENGTH))

  return {
    ok: true,
    targetLine,
    request: {
      file_path: relativePath.replace(/\\/g, '/'),
      content_hash: contentHash(text),
      language,
      target_line: targetLine,
      excerpt_start_line: start,
      excerpt_lines: excerpt,
    },
  }
}

// --------------------------------------------------------------------------
// Validation de la proposition
// --------------------------------------------------------------------------

export interface ProposalContext {
  findingId: string
  relativePath: string
  /** Empreinte du fichier au moment de la demande. */
  baseHash: string
  targetLine: number
  /** Lignes **réelles** du fichier au moment de la demande. */
  lines: readonly string[]
}

export type ProposalVerdict =
  | { ok: true; proposal: SecurityFixProposal }
  | { ok: false; reason: string }

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

/**
 * La proposition est-elle sûre à montrer — et donc à appliquer ?
 *
 * Le backend a déjà validé. Ce contrôle ne lui fait pas confiance : une
 * version différente, une réponse altérée, ou un défaut côté serveur ne
 * doivent pas pouvoir faire écrire un secret ou déborder du finding.
 * Toute réponse qui ne passe pas est **rejetée en bloc** : aucun bouton
 * « Appliquer » n'est affiché.
 */
export function validateProposal(raw: unknown, context: ProposalContext): ProposalVerdict {
  const refuse = (reason: string): ProposalVerdict => ({ ok: false, reason })

  if (!isObject(raw) || raw.ai_generated !== true || typeof raw.available !== 'boolean') {
    return refuse(F.malformed)
  }
  for (const forbidden of ['severity', 'status', 'risk_score']) {
    if (forbidden in raw) {
      return refuse(F.forbiddenField(forbidden))
    }
  }
  if (!raw.available) {
    return refuse(typeof raw.refusal === 'string' && raw.refusal ? raw.refusal : F.unsupported)
  }

  const { start_line: start, end_line: end, replacement_lines: replacement } = raw
  if (
    !Number.isInteger(start) ||
    !Number.isInteger(end) ||
    !isStringArray(replacement) ||
    typeof raw.finding_id !== 'string' ||
    typeof raw.file !== 'string' ||
    typeof raw.base_content_hash !== 'string'
  ) {
    return refuse(F.malformed)
  }
  const first = start as number
  const last = end as number

  // Borné au finding et au fichier demandés, pour l'état demandé.
  if (raw.finding_id !== context.findingId) {
    return refuse(F.otherFinding)
  }
  if (raw.file !== context.relativePath.replace(/\\/g, '/')) {
    return refuse(F.otherFile)
  }
  if (raw.base_content_hash !== context.baseHash) {
    return refuse(F.fileChanged)
  }

  if (first < 1 || first > last || last > context.lines.length) {
    return refuse(F.outOfRange)
  }
  if (!(first <= context.targetLine && context.targetLine <= last)) {
    return refuse(F.notOnFinding)
  }
  if (last - first + 1 > MAX_RANGE_LINES || replacement.length > MAX_REPLACEMENT_LINES) {
    return refuse(F.tooLarge)
  }

  for (const line of replacement) {
    if (/[\r\n]/.test(line) || line.length > MAX_LINE_LENGTH) {
      return refuse(F.malformed)
    }
    if (line.includes(MASK) || line.includes('[REDACTED]')) {
      return refuse(F.maskedValue)
    }
  }

  // Le moteur de secrets lui-même juge le remplacement : un correctif qui
  // écrirait une clé — réelle ou inventée — est refusé par le même
  // détecteur que celui qui a produit le finding.
  if (scanForSecrets(context.relativePath, replacement.join('\n')).findings.length > 0) {
    return refuse(F.writesSecret)
  }

  const original = context.lines.slice(first - 1, last)
  if (original.length === replacement.length && original.every((line, i) => line === replacement[i])) {
    return refuse(F.noChange)
  }
  if (replacement.every((line) => !line.trim()) && original.some((line) => line.trim())) {
    return refuse(F.deletion)
  }

  return { ok: true, proposal: raw as unknown as SecurityFixProposal }
}

/** Texte complet du fichier une fois la proposition appliquée. */
export function proposedText(text: string, proposal: Pick<SecurityFixProposal, 'start_line' | 'end_line' | 'replacement_lines'>): string {
  const { lines, eol } = splitLines(text)
  const next = [
    ...lines.slice(0, proposal.start_line - 1),
    ...proposal.replacement_lines,
    ...lines.slice(proposal.end_line),
  ]
  return next.join(eol)
}

// --------------------------------------------------------------------------
// Application bornée, avec retour arrière
// --------------------------------------------------------------------------

/** Ce dont l'application a besoin du document. Rien d'autre. */
export interface EditableDocument {
  getText(): string
  isDirty(): boolean
  /** Remplace les lignes `start..end` (à partir de 1, bornes incluses). */
  replaceLines(start: number, end: number, lines: readonly string[]): Promise<boolean>
  /** Remet le document entier à ce texte. Sert au retour arrière. */
  replaceAll(text: string): Promise<boolean>
  save(): Promise<boolean>
}

export type ApplyOutcome =
  | { status: 'applied' }
  /** Le fichier a changé : la proposition est périmée, il faut en redemander une. */
  | { status: 'stale'; reason: string }
  | { status: 'failed'; reason: string; restored: boolean }

/**
 * Applique la proposition — et seulement elle — ou rien.
 *
 * 1. Refus si le document a des modifications non enregistrées, ou si son
 *    contenu n'est plus celui sur lequel la proposition a été calculée.
 * 2. Remplacement de la seule plage proposée.
 * 3. Vérification que le résultat est exactement le texte attendu.
 * 4. Enregistrement.
 *
 * Toute étape qui échoue après une modification déclenche un retour à
 * l'original : le fichier n'est jamais laissé à moitié modifié.
 */
export async function applyBoundedFix(
  document: EditableDocument,
  proposal: SecurityFixProposal,
  baseHash: string
): Promise<ApplyOutcome> {
  if (document.isDirty()) {
    return { status: 'stale', reason: F.unsaved }
  }

  const original = document.getText()
  if (contentHash(original) !== baseHash) {
    return { status: 'stale', reason: F.fileChanged }
  }

  const expected = proposedText(original, proposal)

  const restore = async (reason: string): Promise<ApplyOutcome> => {
    let restored = document.getText() === original
    if (!restored) {
      try {
        restored = (await document.replaceAll(original)) && document.getText() === original
      } catch {
        restored = false
      }
    }
    return { status: 'failed', reason, restored }
  }

  let replaced: boolean
  try {
    replaced = await document.replaceLines(
      proposal.start_line,
      proposal.end_line,
      proposal.replacement_lines
    )
  } catch {
    return restore(F.applyFailed)
  }
  if (!replaced) {
    return restore(F.applyFailed)
  }

  if (document.getText() !== expected) {
    return restore(F.unexpectedResult)
  }

  let saved: boolean
  try {
    saved = await document.save()
  } catch {
    saved = false
  }
  if (!saved) {
    return restore(F.saveFailed)
  }

  return { status: 'applied' }
}

/**
 * Demande la confirmation, puis applique — et rien sans elle.
 *
 * `confirm` est la fenêtre modale de l'éditeur. Tant qu'elle n'a pas
 * répondu oui, le document n'est ni lu pour écriture, ni modifié. Séparé
 * de l'éditeur pour que cette promesse se vérifie en test : une réponse
 * négative — ou une fenêtre fermée — ne produit aucune écriture.
 */
export async function confirmAndApply(
  confirm: () => Promise<boolean>,
  document: EditableDocument,
  proposal: SecurityFixProposal,
  baseHash: string,
  onConfirmed: () => void = () => undefined
): Promise<ApplyOutcome | { status: 'not_confirmed' }> {
  let confirmed = false
  try {
    confirmed = await confirm()
  } catch {
    confirmed = false
  }
  if (!confirmed) {
    return { status: 'not_confirmed' }
  }
  onConfirmed()
  return applyBoundedFix(document, proposal, baseHash)
}

// --------------------------------------------------------------------------
// Vérification : ce que disent les moteurs, pas l'IA
// --------------------------------------------------------------------------

export type Verification = 'resolved' | 'still_present' | 'unverified'

/**
 * Le moteur signale-t-il toujours ce problème dans ce fichier ?
 *
 * Correspondance par nature et par fichier, pas par identifiant : un
 * correctif qui décale les lignes change l'identifiant d'un secret resté
 * en place, et conclure « corrigé » sur ce seul changement serait faux.
 * Le doute penche vers « toujours présent ».
 */
export function stillDetected(before: CodeFinding, after: readonly CodeFinding[]): boolean {
  return after.some((candidate) => {
    if (candidate.status !== 'open' || candidate.file_path !== before.file_path) {
      return false
    }
    if (isProjectFinding(before)) {
      return (
        isProjectFinding(candidate) &&
        candidate.detection_engine === before.detection_engine &&
        candidate.category === before.category &&
        candidate.title === before.title
      )
    }
    return !isProjectFinding(candidate) && candidate.rule_id === before.rule_id
  })
}
