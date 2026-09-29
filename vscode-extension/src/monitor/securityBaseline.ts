/**
 * État local de la sécurité du projet, fichier par fichier.
 *
 * Pourquoi cette pièce existe
 * ---------------------------
 *
 * Les routes `POST /api/project/{uid}/secrets` et `.../dependencies`
 * **réconcilient** : le backend aligne ce qu'il a en base sur ce que le
 * balayage lui annonce, conserve les décisions de l'utilisateur par
 * empreinte, et supprime ce qui a disparu. C'est le bon comportement —
 * c'est lui qui empêche un faux positif écarté de revenir à chaque
 * balayage.
 *
 * Mais il a une conséquence directe : soumettre le seul fichier qui vient
 * de changer effacerait les secrets de tous les autres. Réanalyser le
 * projet entier à chaque sauvegarde ferait exactement ce que la phase 3
 * s'interdit.
 *
 * D'où ce registre : il conserve **ce que le dernier parcours complet a
 * constaté**, par fichier et par manifeste. Un fichier modifié remplace
 * sa seule entrée, et le lot complet est reconstitué sans toucher au
 * disque. Le backend reçoit un balayage cohérent, sa réconciliation
 * fonctionne comme avant, et rien n'est relu.
 *
 * Ce qu'il ne conserve jamais
 * ---------------------------
 *
 * Aucun contenu de fichier, aucune valeur de secret. Les constats retenus
 * portent des preuves **déjà expurgées** par `secretScanner.ts` —
 * `sk-proj-********` — et rien d'autre ne transite par ici.
 *
 * Ce qu'il ne fait pas
 * --------------------
 *
 * Il ne crée **aucune seconde architecture de findings** : il ne connaît
 * ni `SecurityFinding`, ni la vue, ni les diagnostics. Il produit les
 * mêmes charges utiles que la découverte complète, et les findings
 * continuent de venir du backend, par le chemin existant.
 *
 * Aucune dépendance à `vscode` : ce module est testable en Node pur.
 */

import type {
  ApiFindingSubmission,
  DependencyRecord,
  SecretFindingSubmission,
} from '../security/securityTypes'
import type { ProjectApiScan } from '../apisec/apiScanner'
import type { ProjectInventory } from '../security/dependencyInventory'
import type { ProjectSecretScan } from '../security/secretScanner'

/**
 * Instantané produit par une découverte complète.
 *
 * Fourni par `projectContext.discover()`, qui le tient des accumulateurs
 * déjà remplis pendant le parcours : rien n'est recalculé pour
 * l'obtenir, et aucun fichier n'est relu.
 */
export interface BaselineSnapshot {
  /** Chemins réellement passés au moteur de secrets. */
  readonly scannedPaths: ReadonlySet<string>
  /** Constats par fichier. Seuls les fichiers porteurs y figurent. */
  readonly secretsByFile: ReadonlyMap<string, readonly SecretFindingSubmission[]>
  /** Dépendances par manifeste lu. */
  readonly dependenciesByManifest: ReadonlyMap<string, readonly DependencyRecord[]>
  /** Constats de sécurité d'API par fichier (phase 5). */
  readonly apiByFile: ReadonlyMap<string, readonly ApiFindingSubmission[]>
  /** Routes relevées pendant le parcours. Dit la couverture. */
  readonly endpointsDetected: number
  readonly skippedFiles: number
  readonly truncated: boolean
}

const SEVERITY_RANK: Readonly<Record<string, number>> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
}

export class SecurityBaseline {
  /** Fichiers passés au moteur de secrets, porteurs ou non. */
  private scanned = new Set<string>()
  /** Constats par fichier — uniquement les fichiers porteurs. */
  private secrets = new Map<string, SecretFindingSubmission[]>()
  private manifests = new Map<string, DependencyRecord[]>()
  /** Constats d'API par fichier — uniquement les fichiers porteurs. */
  private apiFindings = new Map<string, ApiFindingSubmission[]>()
  private endpointsDetected = 0
  private skippedFiles = 0
  private truncated = false
  private established = false

  /**
   * Le registre décrit-il un parcours réel ?
   *
   * Faux tant qu'aucune découverte n'a abouti dans cette session. La
   * distinction est vitale : soumettre un lot reconstitué depuis un
   * registre vide annoncerait au backend « ce projet n'a plus aucun
   * secret », et supprimerait tout ce qu'il savait. Le surveillant refuse
   * donc de soumettre tant que ce drapeau est faux.
   */
  get isEstablished(): boolean {
    return this.established
  }

  get trackedFiles(): number {
    return this.scanned.size
  }

  get filesWithSecrets(): number {
    return this.secrets.size
  }

  get trackedManifests(): number {
    return this.manifests.size
  }

  /** Reprend l'instantané d'une découverte complète. Remplace tout. */
  adopt(snapshot: BaselineSnapshot): void {
    this.scanned = new Set(snapshot.scannedPaths)
    this.secrets = new Map()
    for (const [path, findings] of snapshot.secretsByFile) {
      if (findings.length > 0) {
        this.secrets.set(path, [...findings])
      }
    }
    this.manifests = new Map()
    for (const [path, records] of snapshot.dependenciesByManifest) {
      this.manifests.set(path, [...records])
    }
    this.apiFindings = new Map()
    for (const [path, findings] of snapshot.apiByFile) {
      if (findings.length > 0) {
        this.apiFindings.set(path, [...findings])
      }
    }
    this.endpointsDetected = snapshot.endpointsDetected
    this.skippedFiles = snapshot.skippedFiles
    this.truncated = snapshot.truncated
    this.established = true
  }

  /** Oublie tout : changement de dossier ouvert, ou vidage de la vue. */
  clear(): void {
    this.scanned.clear()
    this.secrets.clear()
    this.manifests.clear()
    this.apiFindings.clear()
    this.endpointsDetected = 0
    this.skippedFiles = 0
    this.truncated = false
    this.established = false
  }

  /**
   * Remplace les constats d'un fichier.
   *
   * Retourne `true` si l'état a réellement changé. Un fichier réanalysé
   * qui rend exactement les mêmes constats ne justifie **aucune**
   * soumission : le backend recevrait un lot identique à celui qu'il a
   * déjà, et le trajet réseau serait pure perte.
   */
  setFileSecrets(
    relativePath: string,
    findings: readonly SecretFindingSubmission[]
  ): boolean {
    const wasScanned = this.scanned.has(relativePath)
    this.scanned.add(relativePath)

    const previous = this.secrets.get(relativePath) ?? []
    const unchanged = sameFindings(previous, findings)

    if (findings.length === 0) {
      this.secrets.delete(relativePath)
    } else {
      this.secrets.set(relativePath, [...findings])
    }

    return !unchanged || !wasScanned
  }

  /**
   * Retire un fichier du registre.
   *
   * Appelé à la suppression, et au moment où un fichier devient illisible
   * ou dépasse le plafond de lecture : dans les deux cas, on ne peut plus
   * rien affirmer de son contenu, et le laisser ferait afficher un secret
   * dans un fichier qui n'existe plus.
   */
  removeFile(relativePath: string): boolean {
    const hadSecrets = this.secrets.delete(relativePath)
    const wasScanned = this.scanned.delete(relativePath)
    return hadSecrets || wasScanned
  }

  /** Remplace les dépendances d'un manifeste. `true` si l'état a changé. */
  setManifest(
    relativePath: string,
    records: readonly DependencyRecord[]
  ): boolean {
    const previous = this.manifests.get(relativePath)
    if (previous !== undefined && sameDependencies(previous, records)) {
      return false
    }
    this.manifests.set(relativePath, [...records])
    return true
  }

  removeManifest(relativePath: string): boolean {
    return this.manifests.delete(relativePath)
  }

  /** Le fichier est-il suivi par le registre ? */
  tracksFile(relativePath: string): boolean {
    return this.scanned.has(relativePath)
  }

  tracksManifest(relativePath: string): boolean {
    return this.manifests.has(relativePath)
  }

  /**
   * Reconstitue le balayage complet, dans la forme attendue par le
   * backend.
   *
   * Même tri que `SecretScanAccumulator` : les plus graves d'abord, parce
   * que c'est l'ordre dans lequel on veut les voir si le lot doit être
   * tronqué côté serveur.
   */
  secretScan(): ProjectSecretScan {
    const findings: SecretFindingSubmission[] = []
    for (const batch of this.secrets.values()) {
      findings.push(...batch)
    }
    findings.sort(compareBySeverity)

    return {
      findings,
      scannedFiles: this.scanned.size,
      skippedFiles: this.skippedFiles,
      truncated: this.truncated,
    }
  }

  /**
   * Remplace les constats d'API d'un fichier.
   *
   * Même contrat que `setFileSecrets` : `true` seulement si l'état a
   * réellement changé. Un fichier réanalysé qui rend les mêmes constats
   * ne justifie aucune soumission.
   */
  setFileApiFindings(
    relativePath: string,
    findings: readonly ApiFindingSubmission[],
    endpoints: number
  ): boolean {
    const previous = this.apiFindings.get(relativePath) ?? []
    const unchanged = sameApiFindings(previous, findings)

    if (findings.length === 0) {
      this.apiFindings.delete(relativePath)
    } else {
      this.apiFindings.set(relativePath, [...findings])
    }

    // Le décompte de routes est une couverture, pas un état par fichier :
    // on ne sait pas retrancher la contribution passée d'un fichier sans
    // la conserver, et la conserver pour un simple compteur coûterait
    // plus que le gain. Il est donc repris du parcours de référence et
    // ajusté à la hausse seulement.
    if (endpoints > 0 && !this.apiFiles.has(relativePath)) {
      this.endpointsDetected += endpoints
    }
    this.apiFiles.add(relativePath)

    return !unchanged
  }

  removeApiFile(relativePath: string): boolean {
    this.apiFiles.delete(relativePath)
    return this.apiFindings.delete(relativePath)
  }

  /** Fichiers passés au moteur d'API, porteurs ou non. */
  private apiFiles = new Set<string>()

  get filesWithApiFindings(): number {
    return this.apiFindings.size
  }

  /** Reconstitue l'analyse d'API complète, dans la forme attendue. */
  apiScan(): ProjectApiScan {
    const findings: ApiFindingSubmission[] = []
    for (const batch of this.apiFindings.values()) {
      findings.push(...batch)
    }
    findings.sort(compareApiBySeverity)

    return {
      findings,
      scannedFiles: this.scanned.size,
      endpointsDetected: this.endpointsDetected,
      truncated: this.truncated,
    }
  }

  /** Reconstitue l'inventaire complet des dépendances. */
  inventory(): ProjectInventory {
    const dependencies: DependencyRecord[] = []
    for (const records of this.manifests.values()) {
      dependencies.push(...records)
    }

    return {
      dependencies,
      manifestsRead: this.manifests.size,
      truncated: this.truncated,
    }
  }
}

/**
 * Deux lots de constats décrivent-ils le même état ?
 *
 * La comparaison porte sur ce qui identifie un problème — règle, fichier,
 * ligne, type de secret, gravité — jamais sur la preuve : deux
 * expurgations du même secret sont identiques par construction, et s'en
 * servir n'apporterait rien.
 */
function sameFindings(
  previous: readonly SecretFindingSubmission[],
  next: readonly SecretFindingSubmission[]
): boolean {
  if (previous.length !== next.length) {
    return false
  }
  const before = previous.map(secretKey).sort()
  const after = next.map(secretKey).sort()
  return before.every((value, index) => value === after[index])
}

function secretKey(finding: SecretFindingSubmission): string {
  return [
    finding.rule_id,
    finding.file_path,
    finding.line,
    finding.secret_type,
    finding.severity,
    finding.confidence,
  ].join('|')
}

function sameDependencies(
  previous: readonly DependencyRecord[],
  next: readonly DependencyRecord[]
): boolean {
  if (previous.length !== next.length) {
    return false
  }
  const before = previous.map(dependencyKey).sort()
  const after = next.map(dependencyKey).sort()
  return before.every((value, index) => value === after[index])
}

function sameApiFindings(
  previous: readonly ApiFindingSubmission[],
  next: readonly ApiFindingSubmission[]
): boolean {
  if (previous.length !== next.length) {
    return false
  }
  const before = previous.map(apiKey).sort()
  const after = next.map(apiKey).sort()
  return before.every((value, index) => value === after[index])
}

/**
 * Ce qui identifie un problème d'API.
 *
 * Règle, fichier, ligne, type — jamais la preuve : un extrait de
 * déclaration réécrit à l'identique produirait la même chaîne, et s'en
 * servir n'apporterait rien.
 */
function apiKey(finding: ApiFindingSubmission): string {
  return [
    finding.rule_id,
    finding.file_path,
    finding.line,
    finding.issue_type,
    finding.severity,
  ].join('|')
}

function compareApiBySeverity(
  a: ApiFindingSubmission,
  b: ApiFindingSubmission
): number {
  const bySeverity =
    (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9)
  if (bySeverity !== 0) {
    return bySeverity
  }
  const byPath = a.file_path.localeCompare(b.file_path)
  return byPath !== 0 ? byPath : a.line - b.line
}

function dependencyKey(record: DependencyRecord): string {
  return [
    record.ecosystem,
    record.name,
    record.version,
    record.direct ? 'd' : 't',
    record.manifest,
    record.source,
  ].join('|')
}

function compareBySeverity(
  a: SecretFindingSubmission,
  b: SecretFindingSubmission
): number {
  const bySeverity =
    (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9)
  if (bySeverity !== 0) {
    return bySeverity
  }
  const byPath = a.file_path.localeCompare(b.file_path)
  return byPath !== 0 ? byPath : a.line - b.line
}
