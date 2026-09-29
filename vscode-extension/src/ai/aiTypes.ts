/**
 * Types de l'assistant IA de sécurité (phase 6), côté extension.
 *
 * Miroir de `backend/app/ai/security_schemas.py`, relié mécaniquement par
 * `contract/api-contract.json` et ses deux tests.
 *
 * Ce qu'aucun de ces types ne porte
 * ---------------------------------
 *
 * - **une gravité produite par l'IA.** La seule gravité présente est
 *   `deterministic_severity`, recopiée par le backend depuis le finding.
 *   Il n'existe donc aucun champ que l'interface pourrait afficher par
 *   erreur à la place de celle du moteur ;
 * - **le contenu d'un fichier.** L'extension envoie un identifiant de
 *   finding, ou une question — jamais du code.
 *
 * `ai_generated` est typé `true` : une réponse d'IA non marquée ne peut
 * pas exister dans ce code.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import type { Severity } from '../security/securityTypes'

/** État de l'assistant, consulté avant d'afficher le moindre bouton IA. */
export interface SecurityAiHealth {
  status: string
  /** Seul booléen à lire : ne jamais recomposer la condition côté client. */
  available: boolean
  chat_available: boolean
  /** Phase 7 : la remédiation assistée est-elle disponible ? */
  fix_available?: boolean
  provider_configured: boolean
  assistant_enabled: boolean
  chat_enabled: boolean
  /** Vide quand l'assistant est indisponible. */
  model: string
  /** Phrase prête à afficher. Vide quand tout est disponible. */
  reason: string
  disclaimer: string
  max_context_findings: number
  modifies_findings: false
  modifies_severity: false
  requires_wazuh: false
}

/** Explication IA d'un finding existant. */
export interface SecurityFindingAiAnalysis {
  finding_id: string
  project_uid: string
  ai_generated: true
  disclaimer: string
  model: string
  analyzed_at: string
  cached: boolean

  // --- Recopie du finding déterministe ---
  category: string
  deterministic_severity: Severity
  deterministic_confidence: string
  deterministic_title: string
  deterministic_remediation: string
  detection_engine: string
  file: string | null
  line: number

  // --- Texte produit par le modèle ---
  explanation: string
  why_it_matters: string
  project_impact: string
  evidence_interpretation: string
  recommendation: string
  remediation_steps: string[]
  secure_example: string
  secure_example_language: string
  related_concepts: string[]
  developer_summary: string
  insufficient_context: boolean
  missing_information: string[]
  confidence: number

  // --- Couverture ---
  project_context_available: boolean
  related_findings_considered: number
}

/** Volumes du projet. Des nombres, jamais des chemins. */
export interface AiFindingCounts {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  by_category: Record<string, number>
}

export interface SecurityAiSummaryRequest {
  /** Liste vide = tous les findings ouverts, bornés côté serveur. */
  finding_ids: string[]
}

/** Résumé IA de plusieurs findings. */
export interface SecurityFindingsAiSummary {
  project_uid: string
  ai_generated: true
  disclaimer: string
  model: string
  analyzed_at: string
  summary: string
  themes: string[]
  relationships: string[]
  priority_order: string[]
  insufficient_context: boolean
  missing_information: string[]
  findings_considered: number
  findings_available: number
  truncated: boolean
  severity_counts: AiFindingCounts
  project_context_available: boolean
}

export interface SecurityChatTurn {
  role: 'user' | 'assistant'
  message: string
}

export interface SecurityChatRequest {
  question: string
  history: SecurityChatTurn[]
  /** Question posée depuis la fiche d'un signalement. */
  finding_id?: string | null
}

export interface SecurityChatResponse {
  project_uid: string
  ai_generated: true
  disclaimer: string
  model: string
  answered_at: string
  /** Question telle qu'elle est partie : **expurgée**. */
  question: string
  answer: string
  insufficient_context: boolean
  missing_information: string[]
  related_concepts: string[]
  findings_considered: number
  findings_available: number
  truncated: boolean
  project_context_available: boolean
  history_turns_used: number
}

// --------------------------------------------------------------------------
// Remédiation assistée (phase 7)
// --------------------------------------------------------------------------

/**
 * Demande de correctif.
 *
 * `excerpt_lines` est un extrait **borné** autour de la ligne visée, déjà
 * expurgé par `redactFreeText` avant l'envoi. Jamais le fichier entier ;
 * `content_hash` en est l'empreinte, qui sert à refuser d'appliquer une
 * proposition à un fichier qui a changé.
 */
export interface SecurityFixRequest {
  file_path: string
  content_hash: string
  language: string
  target_line: number
  excerpt_start_line: number
  excerpt_lines: string[]
}

/**
 * Proposition de correctif, ou refus motivé.
 *
 * Ni gravité produite par l'IA, ni statut : la seule gravité est
 * `deterministic_severity`. `available: false` signifie « pas de
 * modification automatique sûre » — jamais « rien à corriger ».
 */
export interface SecurityFixProposal {
  finding_id: string
  project_uid: string
  kind: 'security' | 'code'
  ai_generated: true
  disclaimer: string
  model: string
  generated_at: string
  category: string
  deterministic_severity: Severity
  deterministic_title: string
  available: boolean
  refusal: string
  file: string
  base_content_hash: string
  start_line: number
  end_line: number
  replacement_lines: string[]
  explanation: string
  reason: string
  warnings: string[]
  manual_steps: string[]
}
