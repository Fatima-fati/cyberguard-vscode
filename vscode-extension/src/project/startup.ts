/**
 * Ordre du démarrage de l'extension.
 *
 * Trois étapes, dans cet ordre imposé :
 *
 *     1. contrôle du backend     établit `project_security_enabled`
 *     2. découverte du projet    lit ce drapeau pour lancer les analyses de
 *                                sécurité, et fixe le `project_uid`
 *     3. reprise de l'historique filtrée par ce `project_uid`
 *
 * Lancées de front, la découverte partait avant la réponse du backend :
 * sans analyse de sécurité, donc sans parcours de référence, et la
 * surveillance des secrets restait en attente toute la session. La reprise
 * partait sans `project_uid` : elle ramenait les findings de tous les
 * projets du backend, filtrés seulement par l'existence locale d'un fichier
 * de même chemin.
 *
 * Aucune dépendance à `vscode` : l'ordre est testable en Node pur.
 */

export interface StartupSteps {
  /** Un dossier est-il ouvert ? */
  readonly folderOpen: boolean
  readonly discoverOnStartup: boolean
  readonly syncOnStartup: boolean
  /** Contrôle du backend. `syncHistory` : reprendre l'historique aussitôt. */
  readonly checkBackend: (syncHistory: boolean) => Promise<void>
  readonly discover: () => Promise<void>
  readonly projectUid: () => string | undefined
  readonly syncHistory: () => Promise<void>
}

export async function runStartup(steps: StartupSteps): Promise<void> {
  // Aucun dossier : aucun projet à attendre. La reprise non filtrée reste
  // le comportement d'un fichier ouvert isolément.
  await steps.checkBackend(!steps.folderOpen)
  if (!steps.folderOpen) {
    return
  }

  if (steps.discoverOnStartup) {
    await steps.discover()
  }

  // Sans identifiant de projet, pas de reprise : mieux vaut une vue vide
  // qu'une vue garnie des findings d'un autre projet.
  if (steps.syncOnStartup && steps.projectUid()) {
    await steps.syncHistory()
  }
}
