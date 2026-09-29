/**
 * Textes affichés à l'utilisateur, regroupés ici.
 *
 * Même règle que côté backend (`app/i18n.py`) : l'interface est en
 * français, mais les identifiants techniques (CWE, OWASP, noms de règles,
 * chemins, codes HTTP) et les termes de sécurité reconnus (SQL injection,
 * XSS, brute force…) restent tels quels.
 */

/**
 * Saut de ligne, nommé plutôt qu'écrit.
 *
 * Les messages multilignes de ce fichier sont assemblés par `join` : la
 * constante évite qu'un `
` écrit à la main dans un gabarit soit lu comme
 * une séquence d'échappement par l'outil qui édite ce fichier.
 */
const NEWLINE = String.fromCharCode(10)

export const FR = {
  // --- Identité ---------------------------------------------------------
  extensionName: 'Wazuh Security',
  outputChannel: 'Wazuh Security',
  diagnosticSource: 'Wazuh Security',

  // --- Barre d'état -----------------------------------------------------
  statusIdle: 'Sécurité : en attente',
  statusEnriching: 'Sécurité : analyse IA…',
  statusTooltipEnriching:
    "Les règles ont déjà répondu ; l'analyse IA affine les résultats.",
  statusTooltipEnrichmentFailed:
    "L'analyse IA a échoué. Les résultats des règles restent valables.",
  statusOk: 'Sécurité : OK',
  statusScanning: 'Sécurité : analyse…',
  statusBackendDown: 'Sécurité : backend injoignable',
  statusTooltipOk: 'Aucun problème de sécurité détecté dans ce fichier.',
  statusTooltipScanning: 'Analyse du fichier en cours…',
  statusTooltipIdle: 'Sauvegardez un fichier pour lancer une analyse.',

  // --- Démarrage --------------------------------------------------------
  noWorkspace:
    "Aucun dossier n'est ouvert : l'analyse reste disponible sur les " +
    'fichiers ouverts individuellement.',
  backendAvailable: (version: string, rules: number) =>
    `Backend d'analyse disponible (API ${version}, ${rules} règles).`,
  backendUnavailable: (reason: string) =>
    `Backend d'analyse injoignable : ${reason} L'extension reste active et ` +
    'réessaiera à la prochaine analyse.',

  // --- Analyse ----------------------------------------------------------
  scanUnsupported: (reason: string) => `Fichier non analysé : ${reason}`,
  scanNoDocument: 'Aucun fichier ouvert à analyser.',
  scanFailed: (message: string) => `Analyse impossible : ${message}`,
  /**
   * Analyse terminee, rien a signaler.
   *
   * Une analyse demandee explicitement doit toujours repondre quelque
   * chose : sans ce message, l'utilisateur ne peut pas distinguer un
   * fichier sain d'une commande qui n'a rien fait.
   */
  scanClean: (fileName: string) =>
    `${fileName} analysé : aucun problème de sécurité détecté ` +
    `(règles du backend).`,
  /**
   * Le fichier a change pendant que le backend l'analysait.
   *
   * Le resultat ne decrit plus ce qui est a l'ecran : il est ecarte, et
   * l'utilisateur doit savoir pourquoi sa commande n'a rien affiche.
   */
  scanStale:
    'Le fichier a été modifié pendant l’analyse : le résultat obtenu ne ' +
    'correspond plus à son contenu. Relancez l’analyse.',
  scanCached: 'Contenu inchangé : résultat repris de l’analyse précédente.',

  // --- Notifications ----------------------------------------------------
  //
  // Une seule forme, quelle que soit la gravité : c'est le canal (info,
  // avertissement, erreur) et le marqueur de tête qui varient, pas la
  // structure. Les termes de sécurité restent en anglais, comme les
  // identifiants techniques.
  notify: {
    /**
     * Corps de la bulle.
     *
     * `others` est un décompte réel de problèmes retenus — jamais une
     * estimation, jamais un score inventé.
     */
    body: (
      severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
      title: string,
      file: string,
      line: number,
      others: number
    ) => {
      // Le marqueur distingue HIGH de MEDIUM, que l'API d'affichage rend
      // autrement identiques.
      const marker =
        severity === 'CRITICAL' ? '⛔ ' : severity === 'HIGH' ? '⚠️ ' : ''

      const lines = [
        `${marker}Security vulnerability detected`,
        '',
        title,
        `${file}:${line}`,
        `Severity: ${severity}`,
      ]

      if (others > 0) {
        lines.push('', `+ ${others} autre${others > 1 ? 's' : ''} dans ce lot.`)
      }

      return lines.join('\n')
    },
    viewIssue: 'View Issue',
    analyzeWithAi: 'Analyze with AI',
  },

  // --- Vérification du backend -----------------------------------------
  backendCheckOk: (url: string, version: string, rules: number, ai: boolean) =>
    `Backend joignable sur ${url} — API ${version}, ${rules} règles, ` +
    `enrichissement IA : ${ai ? 'activé' : 'désactivé'}.`,
  backendCheckFailed: (url: string, reason: string) =>
    `Backend injoignable sur ${url} — ${reason}`,

  // --- Erreurs réseau, en clair ----------------------------------------
  errors: {
    unreachable:
      "le serveur ne répond pas. Vérifiez qu'il est démarré et que " +
      'wazuhSecurity.backendUrl est correct.',
    timeout: "le serveur n'a pas répondu dans le délai imparti.",
    cancelled: 'analyse annulée (le fichier a été modifié entre-temps).',
    badRequest: 'la requête a été refusée par le serveur.',
    notFound:
      "la route d'analyse est introuvable. Le backend est peut-être trop " +
      'ancien pour cette extension.',
    invalidContent:
      "le contenu envoyé a été refusé (fichier vide, trop volumineux, ou " +
      'empreinte incorrecte).',
    serverError: 'le serveur a rencontré une erreur interne.',
    badGateway: "le serveur d'analyse a répondu une erreur.",
    unavailable: "l'analyse de code est désactivée côté serveur.",
    invalidJson: "la réponse du serveur est illisible.",
    unexpected: 'erreur inattendue lors de la communication avec le serveur.',
  },

  // --- Filtrage des fichiers -------------------------------------------
  filter: {
    unsupportedLanguage: (language: string) =>
      `le langage « ${language} » n'est pas encore pris en charge.`,
    sensitive:
      'ce fichier est considéré comme sensible (secrets, clés, certificats) ' +
      "et n'est jamais envoyé au serveur.",
    excluded: 'ce chemin fait partie des dossiers exclus.',
    gitignored: 'ce fichier est ignoré par le .gitignore du projet.',
    empty: 'le fichier est vide.',
    tooLarge: (size: number, max: number) =>
      `le fichier est trop volumineux (${size} octets, limite ${max}).`,
    untitled: "le fichier n'a pas encore été enregistré sur le disque.",
  },

  // --- Analyse IA -------------------------------------------------------
  ai: {
    enrichmentStarted: "Analyse IA en cours côté backend…",
    enrichmentFailed: (reason: string) =>
      `L'analyse IA a échoué : ${reason} Les résultats des règles restent affichés.`,
    dismissedByAi: "Écarté par l'analyse IA comme faux positif.",
  },

  // --- Actions rapides --------------------------------------------------
  actions: {
    fixTitle: (summary: string) => `Corriger : ${summary}`,
    fixUnavailable: 'Aucune correction automatique sûre pour ce problème',
    dismissTitle: 'Ignorer ce signalement (faux positif)',
    detailTitle: 'Voir le détail du problème',
    confirmTitle: 'Appliquer cette correction ?',
    confirmDetail: (file: string, line: number, before: string, after: string) =>
      `${file}, ligne ${line}\n\nAvant :\n${before}\n\nAprès :\n${after}\n\n` +
      "La modification est appliquée dans l'éditeur : vous pouvez l'annuler " +
      'par Ctrl+Z.',
    confirmApply: 'Appliquer',
    confirmCancel: 'Annuler',
    applied: (file: string, line: number) =>
      `Correction appliquée dans ${file}, ligne ${line}. Ctrl+Z pour annuler.`,
    applyFailed: "La correction n'a pas pu être appliquée dans l'éditeur.",
    noFix: (reason: string) => `Aucune correction automatique : ${reason}`,
    dismissPrompt: 'Pourquoi ce signalement est-il un faux positif ?',
    dismissPlaceholder: 'Raison (facultative)',
    dismissed: 'Signalement ignoré. Il reste consultable côté backend.',
    findingUnknown: "Ce signalement n'est plus connu de l'éditeur.",
    documentClosed: 'Le fichier concerné n’est plus ouvert.',
  },

  // --- Garde-fous de la correction automatique ---------------------------
  fix: {
    /**
     * Message de dérive, imposé au mot près par la spécification.
     *
     * Affiché seul, sans préfixe ni enrobage : c'est la seule réponse à
     * un fichier qui ne correspond plus à ce qui a été analysé.
     */
    fileChanged:
      "Le fichier a changé depuis l'analyse. Veuillez relancer l'analyse.",
    notLocalFile:
      "Seul un fichier local peut être corrigé : ce document n'en est pas un.",
    outsideWorkspace:
      "Ce fichier n'appartient pas au workspace ouvert : aucune correction n'y " +
      'est appliquée.',
    notOpen:
      "Ce signalement n'est plus ouvert : il a déjà été corrigé ou écarté.",
    multiline:
      'La correction proposée tient sur plusieurs lignes : elle décalerait la ' +
      "numérotation du fichier et n'est pas appliquée automatiquement.",
    noChange: 'La correction proposée est identique à la ligne actuelle.',
    emptyReplacement:
      'La correction proposée viderait la ligne : elle doit être appliquée à ' +
      'la main.',
    /** Confirmation de l'abandon d'un signalement. */
    dismissConfirmTitle: 'Ignorer ce signalement ?',
    dismissConfirmDetail: (title: string, file: string, line: number) =>
      `${title}\n${file}, ligne ${line}\n\n` +
      "Le signalement disparaîtra de l'éditeur et de la vue Security. Il " +
      "n'est pas supprimé : il reste enregistré côté backend, avec la raison " +
      'que vous indiquerez.',
    dismissConfirmAction: 'Ignorer',
    rescanFailed:
      "La correction a été appliquée, mais la nouvelle analyse n'a pas abouti. " +
      'Sauvegardez le fichier pour relancer une analyse.',
  },

  // --- Vue « Security » --------------------------------------------------
  view: {
    severity: {
      critical: 'Critical',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
    },
    total: 'Total',
    openFinding: 'Ouvrir ce signalement',
    findingsCount: (total: number) => `${total} signalement${total > 1 ? 's' : ''}`,
    badge: (total: number) =>
      `${total} signalement${total > 1 ? 's' : ''} de sécurité ouvert${
        total > 1 ? 's' : ''
      }`,
    fileNotFound: (file: string) =>
      `${file} est introuvable dans le workspace : seule la fiche du ` +
      'signalement est affichée.',
    cleared: 'Vue vidée. Les signalements restent consultables côté backend.',

    // Balayage du workspace
    workspaceScanTitle: 'Analyse du workspace…',
    workspaceScanNoFolder:
      "Aucun dossier n'est ouvert : le balayage du workspace n'a rien à analyser.",
    workspaceScanEmpty: 'Aucun fichier pris en charge trouvé dans le workspace.',
    workspaceScanProgress: (done: number, total: number) => `${done}/${total} fichiers`,
    workspaceScanDone: (
      scanned: number,
      requested: number,
      truncated: boolean,
      cancelled: boolean
    ) =>
      `Analyse du workspace ${cancelled ? 'interrompue' : 'terminée'} : ` +
      `${scanned}/${requested} fichier${requested > 1 ? 's' : ''} analysé${
        scanned > 1 ? 's' : ''
      }.` +
      (truncated
        ? ' La liste a été tronquée : tous les fichiers du workspace n’ont pas été analysés.'
        : ''),

    // Rafraîchissement depuis GET /api/code/findings
    refreshDone: (kept: number, ignored: number) =>
      `${kept} signalement${kept > 1 ? 's' : ''} repris du backend` +
      (ignored > 0 ? `, ${ignored} hors du workspace ignoré(s).` : '.'),
    refreshFailed: (reason: string) => `Rafraîchissement impossible : ${reason}`,

    // Analyse IA à la demande
    aiDisabled:
      "L'analyse IA est désactivée côté backend : les règles déterministes " +
      'restent seules en service.',
    aiRequested: (file: string) => `Analyse IA demandée au backend pour ${file}.`,
  },

  // --- Fenêtre de détail ------------------------------------------------
  detail: {
    title: 'Détail du problème',
    location: 'Emplacement',
    references: 'Références',
    score: 'Score de risque',
    confidence: 'Confiance',
    detectedBy: 'Détecté par',
    scoreBreakdown: 'Comment le score a été calculé',
    noFix: 'Correction automatique',
    fixAvailable: 'Une correction automatique est proposée.',
    fixUnavailable: 'Aucune correction automatique : à appliquer manuellement.',
    actionFix: 'Appliquer la correction',
    actionDismiss: 'Ignorer (faux positif)',
    /** Affiché à la place d'un champ vide : jamais de contenu inventé. */
    unavailable: 'Non disponible.',
    category: 'Catégorie',
    severity: 'Gravité',
    status: 'État',
    snippet: 'Extrait',
    explanation: 'Ce qui ne va pas',
    riskFactors: 'Facteurs de risque',
  },

  // --- Adresse du backend -----------------------------------------------
  //
  // Chaque refus dit ce qui ne va pas ET quoi faire. Un message qui se
  // contente de « adresse invalide » laisse l'utilisateur sans piste, et
  // l’extension parait cassee alors qu'elle se protege.
  backendUrl: {
    empty:
      'Adresse du backend vide. Renseignez `wazuhSecurity.backendUrl`, ' +
      'par exemple http://127.0.0.1:8000',
    malformed: (value: string) =>
      `Adresse du backend illisible : « ${value} ». Attendu : ` +
      'http://127.0.0.1:8000',
    protocol: (protocol: string) =>
      `Protocole « ${protocol} » non pris en charge. Seuls http et https ` +
      'sont acceptés.',
    credentials:
      "L’adresse du backend ne doit pas contenir d’identifiants. " +
      "L’extension s’authentifie par en-tête, jamais par l’URL.",
    noHost: "L’adresse du backend ne désigne aucun hôte.",
    notAnOrigin:
      "L’adresse du backend doit être une origine seule (protocole, hôte, " +
      'port), sans chemin ni paramètre.',
    remoteNotAllowed: (host: string) =>
      `Backend distant refusé : ${host}. Le contenu des fichiers analysés ` +
      'quitterait cette machine. Pour l’autoriser, activez ' +
      '`wazuhSecurity.allowRemoteBackend` dans vos réglages utilisateur.',
    /** Repli annoncé : jamais un affaiblissement silencieux. */
    fallback: (url: string) =>
      `Analyse repliée sur le backend local ${url} en attendant une ` +
      'adresse valide.',
    remoteActive: (host: string) =>
      `Backend distant : ${host}. Le contenu des fichiers analysés quitte ` +
      'cette machine.',
    /** Jeton introuvable : la cause la plus probable vient en premier. */
    tokenMissing: (file: string) =>
      "Jeton d’authentification introuvable. Démarrez le backend : il écrit " +
      `son jeton dans ${file}, que l’extension relira automatiquement.`,
    unauthorized:
      "Le backend a refusé l’authentification. Il a peut-être redémarré " +
      'avec un nouveau jeton : relancez la commande, le jeton est relu ' +
      'automatiquement.',
  },

  // --- Contexte de projet -----------------------------------------------
  project: {
    viewTitle: 'Project',
    /** Vue vide : on dit quoi faire, pas seulement qu’il n’y a rien. */
    empty:
      'Aucun projet analysé. Ouvrez un dossier, puis lancez ' +
      '« Refresh Project Security ».',
    noWorkspace:
      "Aucun dossier ouvert : l’agent ne peut pas établir de contexte de " +
      'projet. Les fichiers ouverts isolément restent analysables.',

    // Libellés de la vue
    labelProject: 'Project',
    labelStatus: 'Statut',
    labelTypes: 'Type de projet',
    labelLanguages: 'Languages',
    labelFrameworks: 'Frameworks',
    labelFiles: 'Files',
    labelSensitive: 'Fichiers sensibles',
    labelManifests: 'Manifestes',
    labelConfiguration: 'Configuration',
    labelGit: 'Dépôt Git',
    labelLastDiscovery: 'Dernière découverte',
    labelWarnings: 'Avertissements',

    gitDetected: 'Détecté',
    gitAbsent: 'Aucun',
    none: 'Aucun',
    unknown: 'Indéterminé',

    status: {
      discovery: 'Découverte en cours',
      security_scan: 'Analyse de sécurité',
      analysis: 'Analyse IA',
      ready: 'Prêt',
      error: 'Erreur',
    },

    /** Un langage sans règles est annoncé comme tel : pas de fausse couverture. */
    languageDetail: (files: number, share: number, supported: boolean) =>
      `${files} fichier${files > 1 ? 's' : ''} · ${share} %` +
      (supported ? '' : ' · aucune règle disponible'),
    frameworkDetail: (evidence: string, source: string) => `${evidence} — ${source}`,
    sensitiveDetail: (reason: string) => reason,
    filesDetail: (indexed: number, discovered: number, truncated: boolean) =>
      truncated
        ? `${indexed} indexés sur ${discovered} trouvés (tronqué)`
        : `${indexed} indexés`,

    // Progression et résultats
    discovering: 'Découverte du projet…',
    discoveringDetail: (indexed: number) => `${indexed} fichiers indexés`,
    discoveryDone: (name: string, indexed: number, sensitive: number) =>
      `Contexte de ${name} établi : ${indexed} fichier${
        indexed > 1 ? 's' : ''
      } indexé${indexed > 1 ? 's' : ''}` +
      (sensitive > 0
        ? `, ${sensitive} fichier${sensitive > 1 ? 's' : ''} sensible${
            sensitive > 1 ? 's' : ''
          } repéré${sensitive > 1 ? 's' : ''}.`
        : '.'),
    discoveryWithWarnings: (count: number) =>
      `Découverte du projet terminée avec ${count} avertissement${
        count > 1 ? 's' : ''
      }. Détails dans le canal « Wazuh Security ».`,
    discoveryCancelled: 'Découverte du projet interrompue.',
    discoveryFailed: (reason: string) => `Découverte du projet impossible : ${reason}`,
    backendUnavailable:
      'Backend indisponible : le contexte de projet ne peut pas être établi. ' +
      'Démarrez le backend Security Agent puis réessayez.',
    alreadyRunning: 'Une découverte de projet est déjà en cours.',

    /** Avertissements de découverte : chaque plafond atteint est annoncé. */
    warnings: {
      truncated: (indexed: number, limit: number) =>
        `Index tronqué à ${indexed} fichiers (plafond ${limit}). La ` +
        "couverture annoncée est partielle : l’agent ne connaît pas tout le projet.",
      unreadableDirectories: (count: number) =>
        `${count} dossier${count > 1 ? 's' : ''} n’a pas pu être parcouru ` +
        '(droits insuffisants ou dossier supprimé pendant la découverte).',
      unreadableFiles: (count: number) =>
        `${count} fichier${count > 1 ? 's' : ''} n’a pas pu être inspecté.`,
      symlinks: (count: number) =>
        `${count} lien${count > 1 ? 's' : ''} symbolique${
          count > 1 ? 's' : ''
        } ignoré${count > 1 ? 's' : ''} : un lien peut pointer hors du workspace.`,
      depth: (limit: number) =>
        `Arborescence plus profonde que ${limit} niveaux : les niveaux ` +
        'inférieurs ne sont pas indexés.',
      manifestTooLarge: (file: string) =>
        `${file} dépasse la taille attendue d’un manifeste : il n’a pas été lu.`,
      manifestUnreadable: (file: string) => `${file} n’a pas pu être lu.`,
    },
  },

  // --- Sécurité projet (phase 2) ---------------------------------------
  //
  // Règle tenue dans tout ce bloc : **aucune formulation ne dit « aucune
  // vulnérabilité » quand le fournisseur n'a pas répondu.** Les phrases
  // qui décrivent l'état du fournisseur viennent du backend
  // (`app.i18n.PROVIDER_STATUS_MESSAGES`) et sont reprises telles quelles ;
  // celles d'ici ne servent que lorsque la vérification a bien eu lieu.
  security: {
    // Progression
    scanning: 'Analyse de sécurité du projet…',
    scanningSecrets: 'Recherche de secrets…',
    scanningDependencies: 'Inventaire des dépendances…',
    alreadyRunning: 'Une analyse de sécurité du projet est déjà en cours.',
    disabledByBackend:
      "Le backend ne porte pas le moteur de sécurité projet : secrets et " +
      'dépendances ne peuvent pas être analysés. Mettez le backend à jour.',
    noProject:
      "Aucun contexte de projet établi : lancez d'abord " +
      '« Refresh Project Security ».',

    // Résultats
    secretsSummary: (total: number, files: number, scanned: number) =>
      total === 0
        ? `Aucun secret détecté dans ${scanned} fichier${
            scanned > 1 ? 's' : ''
          } analysé${scanned > 1 ? 's' : ''}.`
        : `${total} secret${total > 1 ? 's' : ''} détecté${
            total > 1 ? 's' : ''
          } dans ${files} fichier${files > 1 ? 's' : ''}.`,
    dependenciesSummary: (total: number, direct: number) =>
      `${total} dépendance${total > 1 ? 's' : ''} inventoriée${
        total > 1 ? 's' : ''
      } (${direct} directe${direct > 1 ? 's' : ''}).`,
    /**
     * Bilan des vulnérabilités — **uniquement** quand le fournisseur a
     * répondu.
     *
     * Le nombre de dépendances non vérifiées est toujours affiché, même
     * nul : sans lui, « 0 vulnérabilité » se lirait comme « tout est sûr »
     * alors qu'une partie des dépendances peut n'avoir jamais été
     * interrogée.
     */
    vulnerabilitiesSummary: (total: number, unverified: number) => {
      const head =
        total === 0
          ? 'Aucune vulnérabilité connue sur les dépendances vérifiées.'
          : `${total} vulnérabilité${total > 1 ? 's' : ''} connue${
              total > 1 ? 's' : ''
            } sur les dépendances vérifiées.`
      return unverified > 0
        ? `${head} ${unverified} dépendance${
            unverified > 1 ? 's' : ''
          } n'a pas pu être vérifiée (version non figée ou écosystème non couvert).`
        : head
    },

    // Échecs
    scanFailed:
      "L'analyse de sécurité du projet n'a pas abouti. Les résultats " +
      'précédents restent affichés.',
    secretsFailed: (reason: string) =>
      `Recherche de secrets non enregistrée : ${reason}`,
    dependenciesFailed: (reason: string) =>
      `Inventaire des dépendances non enregistré : ${reason}`,

    // Notification d'un secret, forme imposée par la spécification.
    secretNotification: (
      file: string,
      line: number,
      type: string,
      confidence: string
    ) =>
      [
        '🚨 Secret detected',
        '',
        `File: ${file}`,
        `Line: ${line}`,
        `Type: ${type}`,
        `Confidence: ${confidence}`,
      ].join(NEWLINE),
    vulnerabilityNotification: (packageName: string, identifier: string) =>
      ['🚨 Vulnerable dependency', '', packageName, identifier].join(NEWLINE),

    // Vue « Project »
    labelSecrets: 'Secrets',
    labelDependencies: 'Dépendances',
    labelVulnerabilities: 'Vulnérabilités',
    secretsDetail: (total: number, files: number) =>
      total === 0
        ? 'Aucun'
        : `${total} dans ${files} fichier${files > 1 ? 's' : ''}`,
    secretsNeverScanned: 'Jamais analysé',
    dependenciesDetail: (total: number, direct: number, transitive: number) =>
      total === 0
        ? 'Aucune'
        : `${total} · ${direct} directe${
            direct > 1 ? 's' : ''
          } / ${transitive} transitive${transitive > 1 ? 's' : ''}`,
    ecosystemDetail: (total: number, vulnerable: number, verified: number) =>
      `${total} paquet${total > 1 ? 's' : ''}` +
      (vulnerable > 0 ? ` · ${vulnerable} vulnérable${vulnerable > 1 ? 's' : ''}` : '') +
      (verified < total ? ` · ${total - verified} non vérifié(s)` : ''),
    /**
     * Valeur affichée en face de « Vulnérabilités ».
     *
     * Quand le fournisseur n'a pas conclu, on écrit l'état plutôt qu'un
     * chiffre : un « 0 » resterait lisible comme un feu vert même
     * accompagné d'une infobulle que personne n'ouvre.
     */
    vulnerabilitiesDetail: (
      total: number,
      conclusive: boolean,
      statusLabel: string
    ) => (conclusive ? String(total) : statusLabel),
    unverifiedDetail: (count: number) =>
      `${count} dépendance${count > 1 ? 's' : ''} non vérifiée${
        count > 1 ? 's' : ''
      }`,
    /** Rappel affiché en infobulle : l'origine de la donnée compte. */
    providerTooltip: (provider: string, statusLabel: string) =>
      `Fournisseur : ${provider}${NEWLINE}${statusLabel}`,
  },

  // --- Sécurité d'API (phase 5) -----------------------------------------
  api: {
    // Vue « Project »
    label: "Sécurité d'API",
    labelEndpoints: 'Endpoints détectés',
    labelIssues: 'Problèmes d’API',
    labelUnauthenticated: 'Sans authentification',

    /**
     * Valeur affichée en face de « Endpoints détectés ».
     *
     * Ce chiffre dit la **couverture**, pas le risque. Un projet sans
     * route détectée n'est pas un projet sans API : c'est un projet dont
     * l'agent n'a reconnu aucune déclaration — framework non pris en
     * charge, routes montées dynamiquement. L'infobulle le dit.
     */
    endpointsDetail: (total: number) =>
      total === 0 ? 'Aucun reconnu' : String(total),
    endpointsTooltip:
      'Routes déclarées littéralement et reconnues par l’agent. Une route ' +
      'montée dynamiquement, ou un framework non pris en charge, ne ' +
      'figure pas dans ce décompte.',
    issuesDetail: (total: number, scanned: number) =>
      scanned === 0
        ? 'Jamais analysé'
        : total === 0
          ? 'Aucun'
          : String(total),
    unauthenticatedDetail: (total: number) =>
      total === 0 ? 'Aucun' : String(total),

    // Résultat d'une analyse
    summary: (total: number, endpoints: number, scanned: number) =>
      total === 0
        ? `Aucun problème d’API détecté (${endpoints} route${
            endpoints > 1 ? 's' : ''
          } relevée${endpoints > 1 ? 's' : ''} dans ${scanned} fichier${
            scanned > 1 ? 's' : ''
          }).`
        : `${total} problème${total > 1 ? 's' : ''} d’API détecté${
            total > 1 ? 's' : ''
          } sur ${endpoints} route${endpoints > 1 ? 's' : ''} relevée${
            endpoints > 1 ? 's' : ''
          }.`,

    // Échecs
    submissionFailed: (reason: string) =>
      `Analyse d’API non enregistrée : ${reason}`,
    disabledByBackend:
      'Le backend ne porte pas le moteur de sécurité d’API : cette ' +
      'analyse est inactive.',
    disabled: 'Analyse de sécurité d’API désactivée.',

    // Journal — volumes et chemins, jamais d'extrait
    analyzed: (path: string, routes: number, issues: number) =>
      `${path} — ${routes} route(s), ${issues} signalement(s) d’API`,
  },

  // --- Sécurité des changements Git (phase 4) ---------------------------
  git: {
    /** Libellés de gravité, pour un constat produit localement. */
    severity: {
      CRITICAL: 'Critique',
      HIGH: 'Élevée',
      MEDIUM: 'Moyenne',
      LOW: 'Faible',
    },

    // Vue « Project »
    sectionLabel: 'Changements Git',
    branchLabel: 'Branche',
    remoteLabel: 'Remote',
    changedFilesLabel: 'Fichiers modifiés',
    introducedLabel: 'Introduits par ce changement',
    preExistingLabel: 'Préexistants',
    detachedHead: '(branche détachée)',
    noRemote: 'aucun',

    /**
     * Valeur affichée en face de « Introduits ».
     *
     * Quand l'analyse n'a pas conclu, on écrit l'état plutôt qu'un
     * chiffre : un « 0 » resterait lisible comme un feu vert, même
     * accompagné d'une infobulle que personne n'ouvre.
     */
    introducedDetail: (total: number, conclusive: boolean) =>
      conclusive ? (total === 0 ? 'Aucun' : String(total)) : 'Non vérifié',
    preExistingDetail: (total: number) => (total === 0 ? 'Aucun' : String(total)),
    changedFilesDetail: (files: number, added: number, removed: number) =>
      files === 0
        ? 'Aucun'
        : `${files} fichier${files > 1 ? 's' : ''} · +${added} / −${removed}`,

    // États
    noRepository: "Aucun dépôt Git n'est ouvert : il n'y a pas de changement à analyser.",
    noWorkspace: "Aucun dossier ouvert : l'analyse Git n'a rien à examiner.",
    disabled: 'Analyse des changements Git désactivée.',
    apiUnavailable:
      "L'extension Git de VS Code n'est pas disponible : l'analyse des " +
      "changements est inactive. Aucune commande « git » n'est lancée en " +
      'remplacement.',
    timedOut:
      "La vérification des changements n'a pas abouti dans le temps imparti. " +
      'Rien n’est retenu pour autant.',
    analysisFailed: (reason: string) =>
      `Analyse des changements Git impossible : ${reason}`,
    reducedMode: (analyzed: number, total: number) =>
      `Analyse partielle : ${analyzed} fichier${analyzed > 1 ? 's' : ''} sur ` +
      `${total} modifié${total > 1 ? 's' : ''}. Les autres ne sont pas ` +
      'examinés — un changement de cette taille ne peut pas être vérifié ' +
      'en quelques secondes.',

    // Journal — volumes et branche seulement, jamais de preuve
    analysisDone: (
      branch: string,
      files: number,
      introduced: number,
      preExisting: number
    ) =>
      `changements Git analysés sur « ${branch} » — ${files} fichier(s), ` +
      `${introduced} problème(s) introduit(s), ${preExisting} préexistant(s)`,
    branchChanged: (branch: string) =>
      `branche courante : « ${branch} » — attribution recalculée, aucun ` +
      'parcours complet du projet relancé',
    repositoryOpened: (host: string) => `dépôt Git détecté (remote ${host})`,
    repositoryClosed: 'dépôt Git refermé',
    monitorStarted: 'surveillance des changements Git démarrée',
    monitorStopped: 'surveillance des changements Git arrêtée',

    // Vérification avant push
    prePushTitle: 'Vérification avant push',
    prePushClean: (reason: string) => reason,
    prePushWarn: (reason: string) =>
      `⚠️ ${reason} Le push n'est pas bloqué : le réglage est « warn ».`,
    prePushBlock: (reason: string) =>
      `⛔ ${reason} Le réglage « block » demande une confirmation explicite.`,
    prePushReview: 'Voir les problèmes',
    prePushBypass: 'Pousser quand même',
    prePushCancel: 'Annuler',
    prePushBypassed: (count: number) =>
      `contournement accepté par l'utilisateur — ${count} problème(s) ` +
      'introduit(s) non corrigé(s)',
    prePushCancelled: 'push abandonné après la vérification',
    prePushDegraded:
      "La vérification n'a pas pu conclure. Aucun blocage n'est appliqué : " +
      'un agent de sécurité en panne ne doit pas empêcher de travailler.',
    /**
     * Rappel affiché une fois, à l'activation du mode « block ».
     *
     * L'extension n'installe **aucun** hook Git. Le dire est nécessaire :
     * « protection avant push » laisse naturellement croire le contraire,
     * et croire qu'on est protégé sans l'être est pire que de ne pas
     * l'être.
     */
    noHookInstalled:
      "Aucun hook Git n'est installé par l'extension. La vérification " +
      'est lancée depuis l’éditeur, par la commande « Check Changes ' +
      'Before Push ». Un push fait depuis un terminal n’est pas intercepté.',
  },

  // --- Surveillance continue (phase 3) ----------------------------------
  monitor: {
    /**
     * Libellés des trois états de la barre d'état.
     *
     * Les clés restent les états canoniques `READY` / `ANALYZING` /
     * `ERROR` : ce sont eux qu'on lit dans le journal, et faire
     * correspondre les deux à l'œil vaut mieux qu'une table de
     * traduction à retrouver.
     */
    label: {
      READY: 'Surveillance : prête',
      ANALYZING: 'Surveillance : analyse…',
      ERROR: 'Surveillance : erreur',
    },
    icon: {
      READY: '$(eye)',
      ANALYZING: '$(sync~spin)',
      ERROR: '$(warning)',
    },
    tooltip: {
      READY:
        'Les fichiers du projet sont surveillés. ' +
        'Seuls les fichiers réellement modifiés sont réanalysés.',
      ANALYZING: 'Analyse des fichiers modifiés en cours…',
      ERROR:
        'La dernière analyse de surveillance n’a pas abouti. ' +
        'Les résultats précédents restent affichés.',
    },

    started: (debounceMs: number) =>
      `surveillance continue démarrée (anti-rebond ${debounceMs} ms)`,
    stopped: 'surveillance continue arrêtée',
    /** La surveillance attend un parcours complet avant de pouvoir agir. */
    awaitingBaseline:
      'surveillance en attente : aucun parcours de référence dans cette session',
    disabledByBackend:
      'surveillance continue inactive : le backend ne porte pas le moteur ' +
      'de sécurité projet',
    /** Journal d'un changement retenu. Volumes et chemins, jamais de contenu. */
    queued: (path: string, kind: string, priority: string) =>
      `changement retenu — ${path} (${kind}, priorité ${priority})`,
    skipped: (path: string, reason: string) => `changement ignoré — ${path} : ${reason}`,
    unchanged: (path: string) =>
      `${path} — contenu identique, aucune analyse relancée`,
    analyzed: (path: string, analyses: string) =>
      `${path} — surveillance : ${analyses}`,
    failed: (path: string, reason: string) =>
      `${path} — analyse de surveillance en échec : ${reason}`,
    saturated: (dropped: number) =>
      `file de surveillance saturée : ${dropped} travail${
        dropped > 1 ? 'x' : ''
      } abandonné${dropped > 1 ? 's' : ''}`,
    sensitiveChanged: (path: string) =>
      `${path} — fichier sensible modifié, jamais lu : relancez ` +
      '« Scan Project Security » pour le reclasser',
  },

  // --- Assistant IA de sécurité (phase 6) ---------------------------------
  //
  // Deux règles tenues par tous ces libellés :
  //
  // - le texte de l'IA est toujours annoncé comme tel. La mise en garde
  //   elle-même vient du backend (`disclaimer`) : une seule rédaction ;
  // - une indisponibilité se dit « indisponible », jamais « rien à
  //   signaler ». La détection continue sans l'assistant.
  assistant: {
    panelTitle: 'Assistant sécurité (IA)',
    badge: 'Généré par IA',
    loading: 'Analyse IA en cours…',
    chatPending: 'L’assistant rédige sa réponse…',
    unavailableTitle: 'Assistant IA indisponible',
    unavailableDefault:
      'Le backend n’annonce pas d’assistant IA. L’analyse de sécurité ' +
      'continue normalement sans lui.',
    scanningUnaffected:
      'Les signalements, leur gravité et les analyses de sécurité ne ' +
      'dépendent pas de l’assistant.',
    errorTitle: 'L’analyse IA a échoué',
    errorFor: (status: number): string => {
      if (status === 429) {
        return 'Quota du fournisseur d’IA dépassé. Réessayez plus tard.'
      }
      if (status === 504 || status === 408) {
        return 'Le fournisseur d’IA n’a pas répondu à temps.'
      }
      if (status === 502) {
        return 'La réponse de l’IA était inexploitable. Aucun résultat n’a été inventé.'
      }
      return 'L’assistant n’a pas pu répondre.'
    },
    insufficientTitle: 'Contexte insuffisant',
    insufficientText:
      'L’assistant indique ne pas disposer d’assez d’éléments pour ' +
      'répondre de façon fiable.',
    missingInformation: 'Ce qui manque',
    // Rubriques de l'explication
    finding: 'Signalement (moteur de détection)',
    deterministicNote:
      'Gravité et confiance fixées par le moteur déterministe. L’IA ne les modifie pas.',
    explanation: 'Explication',
    whyItMatters: 'Pourquoi c’est important',
    projectImpact: 'Impact pour ce projet',
    evidenceInterpretation: 'Lecture de la preuve',
    recommendation: 'Recommandation',
    steps: 'Étapes',
    secureExample: 'Exemple sécurisé',
    relatedConcepts: 'Concepts liés',
    developerSummary: 'En bref',
    engineRemediation: 'Remédiation proposée par le moteur',
    coverage: (projectContext: boolean, related: number): string =>
      (projectContext
        ? 'Contexte du projet utilisé'
        : 'Aucun contexte de projet (projet non indexé)') +
      ` · ${related} signalement(s) voisin(s) considéré(s)`,
    aiConfidence: (percent: number) =>
      `Confiance de l’IA dans son explication : ${percent} %`,
    cached: 'Explication reprise du cache',
    modelLine: (model: string, at: string) => `Modèle ${model} · ${at}`,
    // Résumé
    summaryTitle: 'Résumé IA des signalements',
    themes: 'Thèmes',
    relationships: 'Relations',
    priorityOrder: 'Ordre de lecture suggéré',
    summaryCoverage: (considered: number, available: number, truncated: boolean): string =>
      `${considered} signalement(s) lu(s) sur ${available}` +
      (truncated ? ' — liste tronquée : le résumé ne porte pas sur tout le projet' : ''),
    // Chat
    chatTitle: 'Chat sécurité',
    chatPlaceholder: 'Posez une question sur la sécurité de ce projet…',
    chatSend: 'Envoyer',
    chatUnavailable: 'Chat indisponible sur ce backend.',
    chatYou: 'Vous',
    chatAssistant: 'Assistant (IA)',
    chatRedacted: 'Des valeurs sensibles ont été masquées avant l’envoi.',
    chatCoverage: (considered: number, available: number, truncated: boolean): string =>
      `Réponse fondée sur ${considered} signalement(s) sur ${available}` +
      (truncated ? ' (contexte tronqué)' : ''),
    actionReanalyze: 'Refaire l’analyse',
    actionSummarize: 'Résumer tous les signalements',
    // Commandes
    noProject:
      'Aucun projet établi : lancez « Refresh Project Security » avant ' +
      'd’utiliser l’assistant.',
    notProjectFinding:
      'L’assistant explique les signalements de sécurité projet (secrets, ' +
      'dépendances, API). Pour ce signalement de code, l’enrichissement IA ' +
      'du code est désactivé côté backend.',
    disabledBySetting:
      'Assistant IA désactivé par le réglage wazuhSecurity.ai.assistant.',
  },

  // --- Remédiation assistée (phase 7) -----------------------------------
  //
  // Toute proposition est annoncée comme générée par une IA, rien n'est
  // appliqué sans confirmation, et le verdict final est celui des moteurs
  // de détection — jamais celui de l'IA.
  remediation: {
    suggestFix: 'Suggest Fix with AI',
    title: 'Correctif proposé (IA)',
    loading: 'L’assistant prépare une proposition de correctif…',
    affected: (file: string, start: number, end: number): string =>
      start === end ? `${file}, ligne ${start}` : `${file}, lignes ${start} à ${end}`,
    currentCode: 'Code actuel (valeurs sensibles masquées)',
    proposedCode: 'Modification proposée',
    explanation: 'Ce que change la modification',
    reason: 'Pourquoi elle corrige le problème',
    warnings: 'Points d’attention',
    manualSteps: 'À faire manuellement',
    apply: 'Appliquer…',
    cancel: 'Annuler',
    showDiff: 'Voir le diff',
    notApplied:
      'Rien n’a été modifié. Le fichier ne sera changé qu’après votre confirmation.',
    confirmTitle: 'Appliquer la modification proposée par l’IA ?',
    confirmDetail: (file: string, start: number, end: number): string =>
      `${start === end ? `Ligne ${start}` : `Lignes ${start} à ${end}`} de ${file}.` +
      ' Cette modification a été générée par une IA : relisez le diff. ' +
      'Le fichier sera enregistré, puis réanalysé par les moteurs de détection.',
    confirmApply: 'Appliquer',
    cancelled: 'Correctif annulé : le fichier n’a pas été modifié.',
    applying: 'Application du correctif…',
    rescanning: 'Nouvelle analyse par les moteurs de détection…',
    resolved:
      'Les moteurs de détection ne signalent plus ce problème dans ce fichier.',
    stillPresent:
      'Les moteurs de détection signalent toujours ce problème : le correctif ' +
      'ne suffit pas. Le signalement reste ouvert.',
    unverified:
      'Correctif appliqué, mais la nouvelle analyse n’a pas pu être menée. ' +
      'Lancez « Scan Project Security » pour vérifier.',
    noDecision:
      'Aucune décision n’est enregistrée par l’IA : seul le résultat de ' +
      'l’analyse fait foi.',
    manualRequired: 'Remédiation manuelle requise',
    restored: 'Le fichier a été restauré dans son état d’origine.',
    notRestored:
      'Le fichier n’a pas pu être restauré automatiquement : utilisez ' +
      'Ctrl+Z ou votre gestionnaire de versions.',
    diffTitle: (file: string) => `${file} — actuel ↔ proposé (IA)`,
    needFresh: 'Demandez une nouvelle proposition.',
    // Éligibilité
    notOpen: 'Ce signalement n’est plus ouvert : aucun correctif n’est proposé.',
    noFile: 'Ce signalement ne porte pas sur un fichier précis : remédiation manuelle requise.',
    protectedFile: (file: string) =>
      `${file} est un fichier protégé (secrets, clés, certificats ou ` +
      'identifiants) : il n’est jamais modifié automatiquement. ' +
      'Remédiation manuelle requise.',
    lockfile: (file: string) =>
      `${file} est un fichier de verrouillage : mettez à jour la dépendance ` +
      'dans le manifeste, puis régénérez-le avec votre gestionnaire de paquets.',
    unsupported: 'Pas de correctif automatique sûr pour ce signalement : remédiation manuelle requise.',
    dependencyNotFound:
      'La déclaration de cette dépendance est introuvable dans le manifeste : ' +
      'relancez l’analyse du projet.',
    lineGone: 'La ligne du signalement n’existe plus : relancez l’analyse.',
    notLocal: 'Seul un fichier local du workspace peut être modifié.',
    fileNotFound: (file: string) => `${file} est introuvable dans le workspace.`,
    unsaved:
      'Le fichier a des modifications non enregistrées : enregistrez-le, puis ' +
      'demandez une nouvelle proposition.',
    disabled: 'Remédiation assistée indisponible sur ce backend.',
    // Rejets de proposition
    malformed: 'La proposition reçue est inexploitable : elle a été rejetée.',
    forbiddenField: (field: string) =>
      `La proposition portait un champ interdit (« ${field} ») : elle a été rejetée.`,
    otherFinding: 'La proposition ne correspond pas à ce signalement : elle a été rejetée.',
    otherFile: 'La proposition vise un autre fichier : elle a été rejetée.',
    fileChanged:
      'Le fichier a changé depuis la proposition : elle n’est plus applicable. ' +
      'Demandez-en une nouvelle.',
    outOfRange: 'La proposition sort du fichier : elle a été rejetée.',
    notOnFinding: 'La proposition ne porte pas sur la ligne du signalement : elle a été rejetée.',
    tooLarge: 'La proposition modifie trop de lignes : elle a été rejetée.',
    maskedValue:
      'La proposition recopiait une valeur masquée : appliquée, elle aurait ' +
      'écrit le masque dans le fichier. Elle a été rejetée.',
    writesSecret: 'La proposition écrivait une valeur de secret : elle a été rejetée.',
    noChange: 'La proposition ne modifie rien : elle a été rejetée.',
    deletion: 'La proposition supprimait du code sans le remplacer : elle a été rejetée.',
    applyFailed: 'L’éditeur a refusé la modification.',
    unexpectedResult: 'Le résultat de la modification n’était pas celui attendu.',
    saveFailed: 'L’enregistrement du fichier a échoué.',
  },

  // --- Posture de sécurité et CI/CD (phase 8) -----------------------------
  //
  // Aucun score. « Non analysé » et « aucun finding » ne s'écrivent jamais
  // de la même façon, et aucun état n'est un « tout va bien ».
  posture: {
    title: 'Posture de sécurité',
    analysis: {
      complete: 'Analyse complète',
      partial: 'Analyse partielle',
      not_analyzed: 'Non analysé',
    } as Record<string, string>,
    analysisTooltip:
      'Lecture des résultats des moteurs de détection, sans score. ' +
      '« Analyse complète » signifie que chaque domaine a été analysé ' +
      'sans troncature — pas que le projet est sûr.',
    findings: 'Findings',
    coverage: 'Couverture',
    filesAnalyzed: 'Fichiers indexés',
    filesDetail: (indexed: number, discovered: number, truncated: boolean): string =>
      truncated ? `${indexed} sur ${discovered} — index tronqué` : `${indexed}`,
    sensitiveFiles: 'Fichiers sensibles (jamais lus)',
    unsupportedLanguages: 'Langages sans règles',
    none: 'Aucun',
    provider: 'Fournisseur de vulnérabilités',
    areas: 'Domaines de sécurité',
    areaNames: {
      secrets: 'Secrets',
      dependencies: 'Dépendances',
      code: 'Code',
      api: 'API',
      git: 'Git',
    } as Record<string, string>,
    state: {
      not_analyzed: 'Non analysé',
      unavailable: 'Indisponible',
      no_findings: 'Aucun finding',
    } as Record<string, string>,
    findingsCount: (count: number) => `${count} finding(s)`,
    partial: 'partiel',
    gitNoRepository: 'Aucun dépôt ouvert',
    gitNotVerified: 'Non vérifié',
    gitIntroduced: (count: number) => `${count} introduit(s) par le changement`,
    gitClean: 'Aucun problème introduit par le changement',
    monitoring: 'Surveillance',
    monitoringState: {
      off: 'Désactivée',
      READY: 'Prête',
      ANALYZING: 'Analyse en cours',
      ERROR: 'Erreur',
    } as Record<string, string>,
    history: 'Historique',
    historyUnavailable: 'Historique insuffisant',
    lastScan: 'Dernière analyse',
    ci: 'CI/CD',
    ciPolicy: (mode: string) => `Politique : ${mode}`,
    ciStatus: {
      off: 'Contrôle désactivé',
      passed: 'Conforme à la politique',
      warning: 'Avertissement',
      blocked: 'Bloquant',
    } as Record<string, string>,
    ciUnavailable: 'Contrôle CI indisponible',
    unavailable: (reason: string) => `Posture indisponible : ${reason}`,
  },

  // --- Diagnostics ------------------------------------------------------
  diagnostic: {
    severity: 'Gravité',
    why: 'Pourquoi c’est dangereux',
    impact: 'Conséquences possibles',
    recommendation: 'Recommandation',
    detectedBy: 'Détecté par',
  },
} as const
