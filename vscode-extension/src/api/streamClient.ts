/**
 * Client SSE du backend — **un seul, pour toute l'extension.**
 *
 * L'analyse fonctionne intégralement sans ce client : le résultat d'un
 * scan arrive dans la réponse HTTP de `/api/code/scan`. Le flux ne sert
 * qu'à recevoir l'enrichissement IA différé, et sa perte est rattrapée
 * par `GET /api/code/scans/{scan_uid}`.
 *
 * Garanties tenues ici :
 *
 * - **une connexion à la fois** — `start()` est idempotent, et une
 *   reconnexion programmée ne peut pas doubler une connexion vivante ;
 * - **reconnexion progressive** — 1 s, 2 s, 4 s, 8 s, 16 s, puis 30 s au
 *   maximum, sans jamais prévenir l'utilisateur : une coupure du flux
 *   n'est pas un incident, l'extension continue de fonctionner ;
 * - **filtrage à la source** — seuls les types d'événements demandés sont
 *   livrés. Les alertes Wazuh et les notifications IA passent sur le même
 *   flux et ne sortent jamais d'ici ;
 * - **rien de sensible dans les journaux** — on trace l'état de la
 *   connexion et le *nom* des événements, jamais leur charge utile, qui
 *   contient des extraits de code.
 *
 * Sur `Last-Event-ID` : le backend sait le lire, mais son rejeu puise dans
 * la table des alertes et ne réémet que `event: alert`. Les événements
 * `code_finding` sont publiés sans `id:` et ne sont pas rejouables. En
 * envoyer un ne rattraperait donc aucun finding et déclencherait un rejeu
 * d'alertes que l'extension jette. La reprise passe par le repli HTTP.
 *
 * Phase 0 — deux ajouts, une seule raison
 * ---------------------------------------
 *
 * Un événement `code_finding` porte un extrait du code analysé. Le flux
 * était ouvert sans authentification et diffusait à tous les abonnés :
 * n'importe quel processus local recevait les extraits de code de tous les
 * projets. D'où :
 *
 * - **`Authorization: Bearer`** à chaque connexion — le flux n'est plus
 *   lisible par un processus quelconque ;
 * - **`?project_uid=`** — le backend n'adresse à ce client que les
 *   événements de son projet.
 *
 * La stratégie de reconnexion est **inchangée** : 1, 2, 4, 8, 16, 30 s,
 * sans notification. Elle fonctionne, et la modifier n'aurait servi aucun
 * objectif de cette phase.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

export interface StreamEvent {
  /** Nom de l'événement SSE (`code_finding`…). */
  event: string
  /** Charge utile déjà décodée. */
  data: unknown
}

/** Base de la temporisation : première tentative après une seconde. */
const BASE_RETRY_MS = 1_000

/** Plafond : au-delà, on cesse d'espacer davantage. */
const MAX_RETRY_MS = 30_000

/**
 * Temporisation avant la n-ième tentative (1 = la première).
 *
 * Doublement à chaque échec, plafonné : 1, 2, 4, 8, 16, 30, 30, 30…
 * Exportée pour être vérifiable sans ouvrir de connexion.
 */
export function retryDelay(attempt: number): number {
  if (attempt < 1) {
    return BASE_RETRY_MS
  }
  // `2 ** 30` dépasse déjà le plafond : borner l'exposant évite un
  // débordement sur une coupure très longue.
  const exponent = Math.min(attempt - 1, 30)
  return Math.min(MAX_RETRY_MS, BASE_RETRY_MS * 2 ** exponent)
}

/** Minuteur annulable. Injectable pour rendre la reconnexion testable. */
export interface Scheduled {
  cancel: () => void
}

export type Scheduler = (callback: () => void, delayMs: number) => Scheduled

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>

export interface StreamClientOptions {
  baseUrl: string
  /**
   * Types d'événements livrés à `onEvent`.
   *
   * Tout le reste est écarté ici même, sans être décodé : l'appelant n'a
   * pas à se défendre contre des événements qui ne le concernent pas.
   */
  events: readonly string[]
  /** Appelé pour chaque événement retenu. Ne doit jamais lever. */
  onEvent: (event: StreamEvent) => void
  /** Journalisation. Ne reçoit jamais de charge utile. */
  onLog?: (message: string) => void
  /** Remplaçable dans les tests. Par défaut : `fetch` global. */
  fetchImpl?: FetchLike
  /** Remplaçable dans les tests. Par défaut : `setTimeout`. */
  scheduler?: Scheduler
  /**
   * En-tête d'authentification, résolu à **chaque** connexion.
   *
   * Résolu à chaque tentative et non une fois pour toutes : le backend a pu
   * redémarrer pendant la coupure avec un nouveau jeton, et une valeur
   * capturée au démarrage condamnerait le flux jusqu'au redémarrage de
   * l'éditeur.
   */
  authHeader?: () => Promise<Record<string, string> | undefined>
  /**
   * Projet dont ce client veut les événements.
   *
   * Résolu à chaque connexion, pour la même raison : le dossier ouvert peut
   * avoir changé. `undefined` = portée globale, ce qui n'apporte **aucun**
   * événement de projet : le backend refuse de livrer un `code_finding` à
   * un abonné qui ne déclare pas son projet.
   */
  projectUid?: () => string | undefined
}

const defaultScheduler: Scheduler = (callback, delayMs) => {
  const timer = setTimeout(callback, delayMs)
  return { cancel: () => clearTimeout(timer) }
}

export class StreamClient {
  private readonly options: StreamClientOptions
  private readonly events: ReadonlySet<string>
  private readonly fetchImpl: FetchLike
  private readonly scheduler: Scheduler

  private controller: AbortController | undefined
  private retry: Scheduled | undefined
  private attempts = 0
  private stopped = true
  /** Une boucle de connexion est-elle déjà en vol ? */
  private active = false

  constructor(options: StreamClientOptions) {
    this.options = options
    this.events = new Set(options.events)
    this.fetchImpl =
      options.fetchImpl ?? ((input, init) => fetch(input, init))
    this.scheduler = options.scheduler ?? defaultScheduler
  }

  /**
   * Ouvre le flux et le maintient ouvert.
   *
   * Idempotent : appeler `start()` sur un client déjà démarré ne crée pas
   * une seconde connexion.
   */
  start(): void {
    if (!this.stopped) {
      return
    }
    this.stopped = false
    this.attempts = 0
    void this.connect()
  }

  /**
   * Ferme proprement : requête interrompue, minuteur annulé.
   *
   * Après cet appel, plus aucune reconnexion n'est programmée et aucune
   * lecture ne se poursuit — condition d'un `deactivate()` sans résidu.
   */
  stop(): void {
    this.stopped = true
    this.cancelRetry()
    this.controller?.abort()
    this.controller = undefined
  }

  dispose(): void {
    this.stop()
  }

  /** Le flux est-il actuellement ouvert ? Utile aux tests et au diagnostic. */
  get connected(): boolean {
    return this.active && !this.stopped
  }

  // ---------------- Interne ----------------

  private cancelRetry(): void {
    this.retry?.cancel()
    this.retry = undefined
  }

  private async connect(): Promise<void> {
    if (this.stopped || this.active) {
      return
    }

    this.active = true
    const controller = new AbortController()
    this.controller = controller

    const base = this.options.baseUrl.replace(/\/+$/, '')
    const project = this.options.projectUid?.()
    const url = project
      ? `${base}/api/stream?project_uid=${encodeURIComponent(project)}`
      : `${base}/api/stream`

    try {
      const authorization = this.options.authHeader
        ? await this.options.authHeader()
        : undefined

      const response = await this.fetchImpl(url, {
        headers: { Accept: 'text/event-stream', ...authorization },
        signal: controller.signal,
      })

      if (!response.ok || !response.body) {
        // Un 401 est trace explicitement : la temporisation progressive
        // rendrait autrement un jeton perime indiscernable d'un backend
        // eteint, alors que les deux se corrigent differemment.
        if (response.status === 401) {
          this.log(
            'flux temps réel refusé : authentification invalide. Le flux ' +
              'sera retenté ; les analyses restent disponibles.'
          )
        }
        throw new Error(`HTTP ${response.status}`)
      }

      // Connexion établie : la prochaine coupure repart d'une seconde.
      this.attempts = 0
      this.log('flux temps réel connecté')
      await this.read(response.body)
    } catch (error) {
      if (this.stopped || controller.signal.aborted) {
        this.active = false
        return
      }
      // Le message d'erreur réseau ne contient aucune charge utile.
      this.log(
        `flux temps réel interrompu : ${
          error instanceof Error ? error.message : String(error)
        }`
      )
    } finally {
      if (this.controller === controller) {
        this.controller = undefined
      }
      this.active = false
    }

    this.scheduleReconnect()
  }

  /** Lit le flux et découpe les événements SSE (séparés par une ligne vide). */
  private async read(body: ReadableStream<Uint8Array>): Promise<void> {
    const reader = body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''

    while (!this.stopped) {
      const { done, value } = await reader.read()
      if (done) {
        return
      }

      buffer += decoder.decode(value, { stream: true })

      // `\r\n\r\n` est toléré : certains intermédiaires normalisent les
      // fins de ligne.
      let separator = nextSeparator(buffer)
      while (separator) {
        const block = buffer.slice(0, separator.index)
        buffer = buffer.slice(separator.index + separator.length)
        this.emit(block)
        separator = nextSeparator(buffer)
      }
    }
  }

  private emit(block: string): void {
    let event = 'message'
    const dataLines: string[] = []

    for (const rawLine of block.split('\n')) {
      const line = rawLine.replace(/\r$/, '')
      // `: heartbeat` : commentaire SSE, à ignorer.
      if (line.startsWith(':')) {
        continue
      }
      if (line.startsWith('event:')) {
        event = line.slice(6).trim()
      } else if (line.startsWith('data:')) {
        dataLines.push(line.slice(5).trim())
      }
      // `id:` et `retry:` sont lus par le navigateur, pas par nous : le
      // rejeu du backend ne concerne que les alertes.
    }

    // Filtrage avant décodage : un événement qui ne nous concerne pas
    // n'est même pas analysé.
    if (!this.events.has(event)) {
      return
    }

    if (dataLines.length === 0) {
      return
    }

    let data: unknown
    try {
      data = JSON.parse(dataLines.join('\n'))
    } catch {
      // Charge utile illisible : on l'ignore, le flux continue. Elle n'est
      // pas journalisée — elle contient des extraits de code.
      this.log(`événement ${event} ignoré : charge utile illisible`)
      return
    }

    try {
      this.options.onEvent({ event, data })
    } catch {
      // Un consommateur défaillant ne doit jamais casser le flux.
    }
  }

  private scheduleReconnect(): void {
    if (this.stopped || this.retry) {
      return
    }

    this.attempts += 1
    const delay = retryDelay(this.attempts)

    // Aucune notification : une coupure du flux n'empêche ni l'analyse,
    // ni les diagnostics, ni la vue. La trace reste dans le canal.
    this.log(`reconnexion au flux dans ${Math.round(delay / 1000)} s`)

    this.retry = this.scheduler(() => {
      this.retry = undefined
      void this.connect()
    }, delay)
  }

  private log(message: string): void {
    this.options.onLog?.(message)
  }
}

/** Prochaine frontière d'événement, en tolérant `\r\n`. */
function nextSeparator(buffer: string): { index: number; length: number } | undefined {
  const plain = buffer.indexOf('\n\n')
  const carriage = buffer.indexOf('\r\n\r\n')

  if (carriage !== -1 && (plain === -1 || carriage < plain)) {
    return { index: carriage, length: 4 }
  }
  if (plain !== -1) {
    return { index: plain, length: 2 }
  }
  return undefined
}
