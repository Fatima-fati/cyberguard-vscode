/**
 * Classement d'un fichier modifié : quelle analyse mérite-t-il ?
 *
 * La surveillance continue ne vaut que si elle est **sélective**. Relancer
 * un parcours complet du projet à chaque sauvegarde serait exactement ce
 * qu'il ne faut pas faire ; lancer une analyse lourde sur un `README.md`
 * ou sur une image l'est presque autant.
 *
 * Ce module répond à une seule question — *que faut-il faire de ce
 * chemin ?* — et il y répond **sans toucher au disque** : il ne reçoit
 * qu'un chemin relatif. La taille, l'empreinte et la date sont l'affaire
 * de `fileSignature.ts`, et le contenu celle des moteurs existants.
 *
 * Ce qu'il ne décide pas
 * ----------------------
 *
 * `documentFilter.evaluate()` reste **la** référence pour ce qui part au
 * backend : un fichier classé `code` ici passe encore par ce filtre avant
 * d'être envoyé. La table d'extensions ci-dessous ne décide donc que
 * d'une chose — vaut-il la peine d'ouvrir ce document ? — et un faux
 * positif y coûte une ouverture de document, jamais un envoi indu.
 *
 * Les listes d'exclusion ne sont pas réécrites : elles sont **importées**
 * de `projectDiscovery.ts`, qui les détient depuis la phase 1. Deux
 * copies auraient fini par diverger, et l'écart se serait vu comme un
 * fichier surveillé ici mais absent de l'index.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import * as path from 'node:path'

import { manifestKind } from '../security/dependencyInventory'
import {
  isBinaryPath,
  isExcludedDirectory,
  isNeverRead,
  type IgnoreMatcher,
} from '../project/projectDiscovery'

/**
 * Nature du fichier, du point de vue de la surveillance.
 *
 * L'ordre de cette liste est l'ordre des contrôles, et il porte une
 * décision : `sensitive` passe avant `dependency` et `code`, comme dans
 * le classement de la phase 1. Un `credentials.json` pourrait ressembler
 * à un manifeste ; s'il était classé comme tel, il serait **lu**.
 */
export type ChangeKind =
  /** Dossier exclu, `.gitignore`, ou hors du dossier ouvert. */
  | 'ignored'
  /** Binaire, média, archive : aucune règle ne s'y applique. */
  | 'binary'
  /** `.env`, `*.pem`, `id_rsa`… : jamais lu, quelle que soit la raison. */
  | 'sensitive'
  /** Manifeste ou fichier de verrouillage : inventaire des dépendances. */
  | 'dependency'
  /** Source dans un langage couvert par le moteur de règles. */
  | 'code'
  /** Autre fichier texte : recherche de secrets seulement. */
  | 'text'

/** Analyses à mener sur ce fichier. Toutes fausses = rien à faire. */
export interface RequiredAnalyses {
  /** Analyse de sécurité du code, par `/api/code/scan`. */
  readonly code: boolean
  /** Recherche de secrets, entièrement locale. */
  readonly secrets: boolean
  /** Inventaire des dépendances déclarées. */
  readonly dependencies: boolean
}

export interface ChangeClassification {
  readonly kind: ChangeKind
  readonly analyses: RequiredAnalyses
  /**
   * Le contenu peut-il être lu ?
   *
   * Faux pour un binaire et pour un fichier sensible. La distinction est
   * faite ici plutôt qu'au moment de la lecture, pour qu'un appelant
   * distrait ne puisse pas ouvrir un `.env` « juste pour vérifier ».
   */
  readonly readable: boolean
  /** Langage attendu par `/api/code/scan`, quand le fichier est du code. */
  readonly language: string | undefined
  /** Motif du classement, destiné au journal. Jamais affiché en bulle. */
  readonly reason: string
}

const NOTHING: RequiredAnalyses = { code: false, secrets: false, dependencies: false }

/**
 * Extensions dont on sait qu'un document VS Code portera un langage
 * couvert par `documentFilter.SUPPORTED_LANGUAGES`.
 *
 * La correspondance est faite par extension, et non par `languageId`,
 * parce que le surveillant ne reçoit qu'un chemin : le document n'est pas
 * nécessairement ouvert. Le `languageId` réel est relu à l'ouverture, et
 * c'est lui qui décide — cette table ne fait qu'éviter d'ouvrir un
 * document pour rien.
 */
const CODE_EXTENSIONS: Readonly<Record<string, string>> = {
  '.py': 'python',
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.mts': 'typescript',
  '.cts': 'typescript',
  '.php': 'php',
  '.java': 'java',
}

/** Le chemin traverse-t-il un dossier que la découverte n'entre jamais ? */
export function crossesExcludedDirectory(relativePath: string): boolean {
  const segments = relativePath.replace(/\\/g, '/').split('/')
  // Le dernier segment est le fichier lui-même : un fichier nommé `build`
  // n'est pas un dossier de build.
  return segments.slice(0, -1).some((segment) => isExcludedDirectory(segment))
}

/**
 * Que faire de ce chemin ?
 *
 * Les contrôles sont ordonnés du plus restrictif au plus permissif, et
 * chacun sort immédiatement : un fichier écarté ne doit pas pouvoir être
 * repêché par un contrôle suivant.
 */
export function classifyChange(
  relativePath: string,
  options: { readonly ignore?: IgnoreMatcher } = {}
): ChangeClassification {
  const normalized = relativePath.replace(/\\/g, '/').replace(/^\.\//, '')

  if (!normalized || normalized.startsWith('../') || path.isAbsolute(normalized)) {
    // Hors du dossier ouvert : la surveillance ne déborde jamais du
    // workspace, même si l'éditeur signale le changement.
    return ignored('chemin hors du dossier ouvert')
  }

  if (crossesExcludedDirectory(normalized)) {
    return ignored('dossier exclu de la découverte')
  }

  if (options.ignore?.ignores(normalized)) {
    return ignored('fichier ignoré par .gitignore')
  }

  // Le classement sensible passe avant tout le reste, comme en phase 1 :
  // un `credentials.json` ressemble à un manifeste, et le classer comme
  // tel reviendrait à le lire.
  if (isNeverRead(normalized)) {
    return {
      kind: 'sensitive',
      analyses: NOTHING,
      readable: false,
      language: undefined,
      reason: 'fichier sensible : jamais lu, signalé par son chemin',
    }
  }

  if (isBinaryPath(normalized)) {
    return {
      kind: 'binary',
      analyses: NOTHING,
      readable: false,
      language: undefined,
      reason: 'fichier binaire : aucune règle ne s’y applique',
    }
  }

  const fileName = normalized.slice(normalized.lastIndexOf('/') + 1)

  if (manifestKind(fileName) !== undefined) {
    // Un manifeste est aussi un fichier texte : un jeton peut s'y glisser
    // (`package.json` et ses scripts, `pyproject.toml` et ses sources).
    // La découverte complète le passe aux deux moteurs ; la surveillance
    // fait de même, sinon la base locale et le projet divergeraient.
    return {
      kind: 'dependency',
      analyses: { code: false, secrets: true, dependencies: true },
      readable: true,
      language: undefined,
      reason: 'manifeste ou fichier de verrouillage',
    }
  }

  const language = CODE_EXTENSIONS[path.extname(normalized).toLowerCase()]
  if (language !== undefined) {
    return {
      kind: 'code',
      analyses: { code: true, secrets: true, dependencies: false },
      readable: true,
      language,
      reason: `source ${language}`,
    }
  }

  // Tout autre fichier lisible : recherche de secrets seulement. C'est
  // une lecture locale et quelques expressions régulières — pas un
  // « scan lourd ». La découverte complète traite ces fichiers de la même
  // façon, et s'en écarter ici ferait diverger la base locale de l'index.
  return {
    kind: 'text',
    analyses: { code: false, secrets: true, dependencies: false },
    readable: true,
    language: undefined,
    reason: 'fichier texte : recherche de secrets seulement',
  }
}

/** Ce classement demande-t-il le moindre travail ? */
export function requiresWork(classification: ChangeClassification): boolean {
  const { code, secrets, dependencies } = classification.analyses
  return code || secrets || dependencies
}

/** Union de deux jeux d'analyses : ce que deux changements exigent ensemble. */
export function mergeAnalyses(
  first: RequiredAnalyses,
  second: RequiredAnalyses
): RequiredAnalyses {
  return {
    code: first.code || second.code,
    secrets: first.secrets || second.secrets,
    dependencies: first.dependencies || second.dependencies,
  }
}

function ignored(reason: string): ChangeClassification {
  return {
    kind: 'ignored',
    analyses: NOTHING,
    readable: false,
    language: undefined,
    reason,
  }
}
