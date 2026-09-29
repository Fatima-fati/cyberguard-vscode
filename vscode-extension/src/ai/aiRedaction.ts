/**
 * Expurgation du texte libre saisi dans le chat de sécurité (phase 6).
 *
 * Une question est du texte libre : un développeur y colle volontiers la
 * ligne qui l'intrigue — `DB_PASSWORD=...` compris. Le backend expurge
 * cette question avant de la transmettre au modèle, et c'est **sa**
 * expurgation qui fait foi. Celle-ci s'ajoute à la sienne pour une raison
 * simple : sans elle, le secret quitterait quand même l'éditeur, et
 * traverserait le réseau jusqu'au backend — qui peut être distant.
 *
 * Aucune liste de motifs nouvelle : ce module rejoue le catalogue du
 * moteur de secrets (`secretPatterns.ts`), pour qu'un secret reconnu par
 * le balayage le soit aussi dans une question. Deux listes finiraient par
 * diverger, et c'est la plus courte qui déciderait de ce qui sort.
 *
 * Différence assumée avec le balayage : ici, **aucun contrôle de faux
 * positif** (entropie, placeholder). Masquer à tort un mot d'une question
 * la rend un peu moins lisible ; laisser passer une clé la rend rejouable.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import { MASK, redactSecret } from '../security/redaction'
import { SECRET_PATTERNS } from '../security/secretPatterns'

/** Longueur maximale d'une question, alignée sur le backend. */
export const MAX_QUESTION_LENGTH = 1000

/** Longueur maximale d'un tour d'historique, alignée sur le backend. */
export const MAX_TURN_LENGTH = 1200

/**
 * Jeton long mêlant lettres et chiffres : la forme d'une clé.
 *
 * Seconde passe, indépendante du catalogue : une clé d'un fournisseur
 * absent de la liste est masquée quand même.
 */
const GENERIC_TOKEN = /[A-Za-z0-9_\-+/=]{24,}/g

function looksLikeKey(token: string): boolean {
  return /[0-9]/.test(token) && /[A-Za-z]/.test(token)
}

/** Texte libre prêt à quitter l'éditeur. */
export function redactFreeText(value: string, limit = MAX_QUESTION_LENGTH): string {
  let text = typeof value === 'string' ? value : ''

  for (const secret of SECRET_PATTERNS) {
    // Copie globale du motif : l'original est sans drapeau `g`, et un
    // `lastIndex` partagé produirait des oublis au hasard.
    const flags = secret.pattern.flags.includes('g')
      ? secret.pattern.flags
      : `${secret.pattern.flags}g`
    const pattern = new RegExp(secret.pattern.source, flags)

    text = text.replace(pattern, (...args: unknown[]) => {
      const whole = String(args[0])
      const captured = secret.valueGroup === 0 ? whole : args[secret.valueGroup]
      if (typeof captured !== 'string' || captured.length === 0) {
        return whole
      }
      if (captured.includes(MASK)) {
        return whole
      }
      return whole.replace(captured, redactSecret(captured, secret.keep))
    })
  }

  text = text.replace(GENERIC_TOKEN, (token) =>
    token.includes(MASK) || !looksLikeKey(token) ? token : redactSecret(token)
  )

  return text.length > limit ? text.slice(0, limit) : text
}
