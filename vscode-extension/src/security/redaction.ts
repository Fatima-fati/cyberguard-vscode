/**
 * Expurgation des valeurs détectées.
 *
 * Le contrat de ce module tient en une phrase : **une valeur qui passe par
 * ici ne peut plus être rejouée.** Ce qui en ressort sert à reconnaître la
 * nature de ce qui a été trouvé — « c'est bien une clé OpenAI » — jamais à
 * s'en servir.
 *
 * Pourquoi l'expurgation a lieu ici, au plus près de la détection
 * ----------------------------------------------------------------
 *
 * La valeur complète n'existe que dans la portée d'un appel de
 * `scanForSecrets`. Elle n'est jamais stockée, jamais journalisée, jamais
 * placée dans un objet qui survivrait à cet appel. Expurger plus tard —
 * au moment de l'envoi, par exemple — laisserait la valeur circuler entre
 * les deux, et il suffirait d'une trace de diagnostic mal placée pour
 * qu'elle atteigne le canal de sortie.
 *
 * Le backend ré-expurge à la réception. Les deux protections sont
 * volontairement redondantes : celle-ci protège le poste (journaux,
 * mémoire, fenêtre de détail), celle du backend protège la base.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

/** Masque unique, pour qu'une preuve reste reconnaissable à la relecture. */
export const MASK = '********'

/**
 * Nombre maximal de caractères de tête conservés.
 *
 * Assez pour reconnaître la nature de la clé (`sk-proj-`, `AKIA`, `ghp_`),
 * trop peu pour la rejouer. La borne est absolue : aucun appelant ne peut
 * demander à en voir davantage.
 */
export const MAX_VISIBLE = 8

/**
 * Longueur en dessous de laquelle **rien** n'est révélé.
 *
 * Sur une valeur courte, montrer même quatre caractères réduirait
 * sérieusement l'espace de recherche. Une valeur courte est donc masquée
 * en entier.
 */
const MIN_LENGTH_TO_REVEAL = 12

/**
 * Masque une valeur détectée.
 *
 * `keep` est une **demande**, pas une garantie : la fonction ne révèle
 * jamais plus de `MAX_VISIBLE` caractères, ni plus du quart de la valeur,
 * ni quoi que ce soit d'une valeur courte. Un appelant ne peut donc pas
 * affaiblir l'expurgation, même par erreur.
 */
export function redactSecret(value: string, keep = 4): string {
  const raw = (value ?? '').trim()
  if (raw.length === 0) {
    return MASK
  }
  if (raw.length < MIN_LENGTH_TO_REVEAL) {
    return MASK
  }

  const visible = Math.max(
    0,
    Math.min(keep, MAX_VISIBLE, Math.floor(raw.length / 4))
  )
  return `${raw.slice(0, visible)}${MASK}`
}

/**
 * Preuve affichable pour un secret détecté.
 *
 * Forme imposée par la spécification : un libellé, puis la valeur
 * masquée.
 *
 *     OpenAI API key detected: sk-proj-********
 *
 * Le libellé reste en anglais, comme les autres identifiants techniques du
 * projet (CWE, OWASP, noms de règles) : c'est ce que le développeur
 * retrouvera dans la documentation du fournisseur.
 */
export function buildEvidence(label: string, value: string, keep = 4): string {
  return `${label}: ${redactSecret(value, keep)}`
}

/**
 * Garde-fou vérifiable : cette chaîne est-elle sûre à conserver ?
 *
 * Utilisée par les tests et par le contrôle de dernière minute avant
 * envoi. Une preuve est refusée dès qu'elle contient une suite de douze
 * caractères ou plus d'alphabet de clé sans masque — c'est la forme d'une
 * valeur qui aurait échappé à `redactSecret`.
 */
export function isRedacted(evidence: string): boolean {
  const text = evidence ?? ''
  // Les segments déjà masqués sont retirés avant l'examen : c'est le
  // reste qui doit être inoffensif.
  const remainder = text.split(MASK).join(' ')
  const tokens = remainder.match(/[A-Za-z0-9_\-+/=]{12,}/g) ?? []

  // Un mot reste un mot : « credentials », « Identifiants » ou un nom de
  // variable ne sont pas des fuites, et les masquer rendrait la preuve
  // illisible sans rien protéger. Tout le reste — un chiffre, un tiret,
  // une longueur inhabituelle — est traité comme une valeur.
  return tokens.every((token) => /^[A-Za-z]+$/.test(token) && token.length <= 20)
}
