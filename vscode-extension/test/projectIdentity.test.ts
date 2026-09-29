/**
 * Tests de l'identité de projet.
 *
 * Trois propriétés à tenir, et chacune a un coût si elle manque :
 *
 *     stable     sans elle, un projet réouvert perd ses findings
 *     distinct   sans elle, deux projets se contaminent
 *     opaque     sans elle, la base révèle l'arborescence du poste
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  normalizeWorkspacePath,
  projectNameOf,
  rootHashOf,
  shortProjectId,
} from '../src/project/projectIdentity'

describe('rootHashOf — forme', () => {
  it('produit un SHA-256 hexadécimal', () => {
    // Le backend refuse toute autre forme : la validation est stricte des
    // deux côtés.
    const hash = rootHashOf('/home/dev/projet')
    assert.equal(hash.length, 64)
    assert.match(hash, /^[0-9a-f]{64}$/)
  })
})

describe('rootHashOf — stabilité', () => {
  it('donne toujours la même empreinte pour le même chemin', () => {
    // Sans cela, un projet réouvert serait vu comme un projet neuf et
    // perdrait ses scans et ses findings.
    assert.equal(rootHashOf('/home/dev/projet'), rootHashOf('/home/dev/projet'))
  })

  it('ignore un slash final', () => {
    assert.equal(rootHashOf('/home/dev/projet'), rootHashOf('/home/dev/projet/'))
  })

  it('ignore le type de séparateur', () => {
    // VS Code fournit tantôt l'un, tantôt l'autre selon le chemin d'appel.
    assert.equal(
      rootHashOf('C:\\Users\\dev\\projet'),
      rootHashOf('C:/Users/dev/projet')
    )
  })

  it('ignore la casse de la lettre de lecteur', () => {
    // Deux empreintes pour un seul dossier dédoubleraient son contexte.
    assert.equal(rootHashOf('c:/Users/dev/projet'), rootHashOf('C:/Users/dev/projet'))
  })

  it('ignore les segments redondants', () => {
    assert.equal(
      rootHashOf('/home/dev/projet'),
      rootHashOf('/home/dev/./sous/../projet')
    )
  })
})

describe('rootHashOf — distinction', () => {
  it('distingue deux dossiers de même nom', () => {
    // Le cas qui motive tout ce module : `folders[0].name` valait « backend »
    // pour les deux, et leurs findings se mélangeaient.
    assert.notEqual(
      rootHashOf('/home/dev/client-a/backend'),
      rootHashOf('/home/dev/client-b/backend')
    )
  })

  it('distingue un dossier de son parent', () => {
    assert.notEqual(rootHashOf('/home/dev'), rootHashOf('/home/dev/projet'))
  })

  it('conserve la casse du reste du chemin', () => {
    // L'uniformiser rendrait indistinguables deux dossiers réellement
    // différents sur un système sensible à la casse — un bug de
    // cloisonnement, exactement ce que cet identifiant doit empêcher.
    assert.notEqual(rootHashOf('/home/dev/Projet'), rootHashOf('/home/dev/projet'))
  })
})

describe('rootHashOf — opacité', () => {
  it('ne laisse apparaître ni le nom d’utilisateur ni le chemin', () => {
    // Le chemin absolu révèle l'identité de l'utilisateur et l'arborescence
    // de son poste.
    const hash = rootHashOf('/home/prenom.nom/projets/client-confidentiel')
    assert.ok(!hash.includes('prenom'))
    assert.ok(!hash.includes('nom'))
    assert.ok(!hash.includes('client'))
    assert.ok(!hash.includes('confidentiel'))
    // Une empreinte hexadécimale ne peut contenir aucun de ces fragments,
    // mais figer la vérification empêche qu'un jour on « améliore »
    // l'identifiant en y glissant le chemin.
    assert.match(hash, /^[0-9a-f]{64}$/)
  })
})

describe('normalizeWorkspacePath', () => {
  const cas: [string, string][] = [
    ['/home/dev/projet', '/home/dev/projet'],
    ['/home/dev/projet/', '/home/dev/projet'],
    ['C:\\Users\\dev\\projet', 'C:/Users/dev/projet'],
    ['c:/users/dev', 'C:/users/dev'],
    ['/', '/'],
  ]

  for (const [input, expected] of cas) {
    it(`normalise « ${input} »`, () => {
      assert.equal(normalizeWorkspacePath(input), expected)
    })
  }
})

describe('projectNameOf', () => {
  it('reprend le dernier segment du chemin', () => {
    const path = '/home/dev/MonApplication'
    assert.equal(projectNameOf(path, rootHashOf(path)), 'MonApplication')
  })

  it('fonctionne avec des séparateurs Windows', () => {
    const path = 'C:\\Users\\dev\\MonApplication'
    assert.equal(projectNameOf(path, rootHashOf(path)), 'MonApplication')
  })

  it('tolère un slash final', () => {
    const path = '/home/dev/MonApplication/'
    assert.equal(projectNameOf(path, rootHashOf(path)), 'MonApplication')
  })

  it('se rabat sur l’empreinte à la racine d’un disque', () => {
    // Il faut bien afficher quelque chose, et ce quelque chose ne doit rien
    // révéler du poste.
    const hash = rootHashOf('C:/')
    const name = projectNameOf('C:/', hash)
    assert.equal(name, `projet-${hash.slice(0, 8)}`)
  })

  it('se rabat sur l’empreinte pour une racine POSIX', () => {
    const hash = rootHashOf('/')
    assert.match(projectNameOf('/', hash), /^projet-[0-9a-f]{8}$/)
  })

  it('ne renvoie jamais le chemin entier', () => {
    const path = '/home/prenom.nom/projets/MonApplication'
    const name = projectNameOf(path, rootHashOf(path))
    assert.equal(name, 'MonApplication')
    assert.ok(!name.includes('/'))
    assert.ok(!name.includes('prenom'))
  })
})

describe('shortProjectId', () => {
  it('produit un identifiant court et stable', () => {
    const hash = rootHashOf('/home/dev/projet')
    assert.equal(shortProjectId(hash), hash.slice(0, 12))
    assert.equal(shortProjectId(hash).length, 12)
  })

  it('distingue encore deux projets de même nom', () => {
    // Les traces doivent rester corrélables sans ambiguïté.
    assert.notEqual(
      shortProjectId(rootHashOf('/home/dev/client-a/backend')),
      shortProjectId(rootHashOf('/home/dev/client-b/backend'))
    )
  })
})
