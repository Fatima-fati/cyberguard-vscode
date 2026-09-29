/**
 * Cache d'empreintes : ce qui évite de réanalyser ce qui n'a pas changé.
 *
 * La phase 1 indexe déjà `size`, `mtime` et `content_hash` pour chaque
 * fichier. Ce module est le consommateur prévu de ce triplet : il s'en
 * sert pour répondre, sans rien envoyer au backend, à la seule question
 * qui compte quand un fichier bouge — *son contenu a-t-il réellement
 * changé ?*
 *
 * Trois niveaux, du moins cher au plus cher
 * -----------------------------------------
 *
 *     taille      un octet de différence suffit à conclure « changé »
 *     date        taille identique + date identique  →  rien n'a bougé
 *     empreinte   date différente mais contenu identique  →  rien n'a bougé
 *
 * Le troisième niveau existe pour un cas très banal : `Ctrl+S` sans avoir
 * rien tapé, un formateur qui réécrit le fichier à l'identique, un
 * `git checkout` qui restaure la même version. Sans lui, chacun de ces
 * gestes déclencherait une analyse complète du fichier.
 *
 * Ce module ne lit **aucun** fichier : l'appelant lui fournit la
 * signature. C'est ce qui le rend testable sans disque, et c'est aussi ce
 * qui garantit qu'il ne peut pas ouvrir un fichier qu'il ne devrait pas.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

/** Ce qu'on retient d'un fichier. `hash` est `null` quand non calculable. */
export interface FileSignature {
  readonly size: number
  readonly mtimeMs: number
  /**
   * Empreinte du contenu, ou `null`.
   *
   * `null` signifie « pas d'empreinte » — fichier trop gros, binaire,
   * sensible ou illisible — **jamais** « fichier inchangé ». La
   * comparaison en tient compte : sans empreinte des deux côtés, on
   * conclut « changé » plutôt que de supposer.
   */
  readonly hash: string | null
}

export type SignatureVerdict =
  /** Jamais vu : il faut l'analyser. */
  | 'new'
  /** Taille et date identiques : rien n'a bougé. */
  | 'unchanged'
  /** Date différente, contenu identique : une sauvegarde sans modification. */
  | 'touched'
  /** Le contenu a changé, ou on ne peut pas prouver le contraire. */
  | 'changed'

/**
 * Faut-il analyser après ce verdict ?
 *
 * `touched` est volontairement distingué de `unchanged` — les deux
 * n'appellent aucun travail, mais ils ne se journalisent pas pareil, et
 * confondre « le fichier n'a pas bougé » avec « il a été réécrit à
 * l'identique » ferait perdre l'explication la plus utile quand un
 * utilisateur demande pourquoi sa sauvegarde n'a rien déclenché.
 */
export function demandsAnalysis(verdict: SignatureVerdict): boolean {
  return verdict === 'new' || verdict === 'changed'
}

export class SignatureCache {
  private readonly entries = new Map<string, FileSignature>()

  /**
   * Compare une signature fraîche à ce qu'on savait du fichier.
   *
   * **Ne modifie rien** : l'enregistrement est une opération distincte,
   * pour que l'appelant puisse décider de ne retenir une signature
   * qu'après une analyse réussie. Retenir avant coup ferait qu'un échec
   * réseau rendrait le fichier « déjà vu », donc jamais réanalysé.
   */
  compare(relativePath: string, fresh: FileSignature): SignatureVerdict {
    const known = this.entries.get(relativePath)
    if (known === undefined) {
      return 'new'
    }

    if (known.size !== fresh.size) {
      return 'changed'
    }

    if (known.mtimeMs === fresh.mtimeMs) {
      return 'unchanged'
    }

    // Date différente : seule l'empreinte peut encore innocenter le
    // fichier. Sans empreinte d'un côté ou de l'autre, on ne suppose
    // rien — un fichier manqué à tort est un angle mort de sécurité, un
    // fichier réanalysé à tort coûte une requête.
    if (known.hash !== null && fresh.hash !== null && known.hash === fresh.hash) {
      return 'touched'
    }

    return 'changed'
  }

  /** Retient la signature d'un fichier. Remplace la précédente. */
  remember(relativePath: string, signature: FileSignature): void {
    this.entries.set(relativePath, signature)
  }

  /**
   * Met à jour la date sans toucher au reste.
   *
   * Sert au cas `touched` : le fichier a été réécrit à l'identique. Garder
   * l'ancienne date ferait reprendre la comparaison d'empreinte à chaque
   * sauvegarde suivante, alors qu'on vient d'établir qu'il n'y a rien à
   * faire.
   */
  refreshTimestamp(relativePath: string, mtimeMs: number): void {
    const known = this.entries.get(relativePath)
    if (known) {
      this.entries.set(relativePath, { ...known, mtimeMs })
    }
  }

  /** Oublie un fichier : il a été supprimé, ou renommé. */
  forget(relativePath: string): void {
    this.entries.delete(relativePath)
  }

  has(relativePath: string): boolean {
    return this.entries.has(relativePath)
  }

  get(relativePath: string): FileSignature | undefined {
    return this.entries.get(relativePath)
  }

  /** Oublie tout : changement de dossier ouvert, ou nouvelle découverte. */
  clear(): void {
    this.entries.clear()
  }

  get size(): number {
    return this.entries.size
  }

  /**
   * Amorce le cache depuis l'index d'une découverte.
   *
   * L'index de la phase 1 porte exactement les trois champs nécessaires.
   * Les reprendre évite de relire tout le projet pour reconstituer ce
   * qu'on vient de calculer — c'est précisément ce que la préparation de
   * cette phase annonçait.
   *
   * Le cache est **remplacé**, pas complété : un fichier disparu de
   * l'index a disparu du projet, et le laisser ici le rendrait
   * indéfiniment « inchangé ».
   */
  adopt(
    files: readonly {
      readonly path: string
      readonly size: number
      /** ISO 8601, ou `null` quand le système de fichiers ne la donne pas. */
      readonly mtime: string | null
      readonly content_hash: string | null
    }[]
  ): void {
    this.entries.clear()
    for (const file of files) {
      const mtimeMs = file.mtime === null ? Number.NaN : Date.parse(file.mtime)
      this.entries.set(file.path, {
        size: file.size,
        // Une date illisible vaut zéro : la comparaison retombera alors
        // sur l'empreinte, ce qui reste correct.
        mtimeMs: Number.isNaN(mtimeMs) ? 0 : mtimeMs,
        hash: file.content_hash,
      })
    }
  }
}
