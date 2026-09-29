/**
 * Tests de la fiche détaillée.
 *
 * Deux exigences, toutes deux vérifiables sans VS Code :
 *
 * 1. **les données affichées sont celles du backend**, et un champ absent
 *    est annoncé « Non disponible. » plutôt que comblé ;
 * 2. **rien de ce que contient le code de l'utilisateur n'est interprété** —
 *    l'extrait remonté par le backend est du texte, pas du HTML.
 *
 * Ce que ces tests **ne** vérifient pas : le rendu visuel de la webview,
 * ni l'application effective de la CSP par le moteur. Ils vérifient que la
 * page déclare la bonne politique et échappe son contenu.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import type { CodeFinding } from '../src/api/backendClient'
import { buildDetailHtml, escapeHtml } from '../src/ui/detailHtml'
import { FR } from '../src/i18n/fr'

const NONCE = 'nOnCe123456789=='

function finding(overrides: Partial<CodeFinding> = {}): CodeFinding {
  return {
    finding_uid: 'uid-1',
    scan_uid: 'scan-1',
    rule_id: 'PY-SQLI-001',
    category: 'injection',
    category_label: 'Injection',
    cwe: 'CWE-89',
    owasp: 'A03:2021',
    severity: 'CRITICAL',
    severity_label: 'Critique',
    risk_score: 92,
    risk_band: 'critique',
    confidence: 0.9,
    source: 'rule',
    source_label: 'Règle déterministe',
    title: 'SQL Injection',
    explanation: 'La valeur est concaténée sans échappement.',
    why_dangerous: 'Un attaquant peut lire toute la table.',
    potential_impact: ['Exfiltration de la base'],
    recommendations: ['Utiliser une requête paramétrée'],
    risk_factors: [{ name: 'Entrée utilisateur', detail: 'directe', weight: 15 }],
    location: {
      line_start: 10,
      line_end: 10,
      column_start: 0,
      column_end: 20,
      snippet: 'query = "SELECT * FROM users WHERE id=" + user_id',
    },
    file_path: 'src/users.py',
    fix_available: false,
    fix_summary: '',
    status: 'open',
    status_label: 'Ouvert',
    created_at: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

describe('escapeHtml', () => {
  it('neutralise les cinq caractères dangereux', () => {
    assert.equal(
      escapeHtml(`<script>alert("x") & 'y'</script>`),
      '&lt;script&gt;alert(&quot;x&quot;) &amp; &#39;y&#39;&lt;/script&gt;'
    )
  })

  it('échappe l’esperluette en premier, sans double échappement', () => {
    // `&lt;` doit devenir `&amp;lt;`, pas `&lt;`.
    assert.equal(escapeHtml('&lt;'), '&amp;lt;')
  })

  it('laisse un texte ordinaire intact', () => {
    assert.equal(escapeHtml('Requête paramétrée'), 'Requête paramétrée')
  })
})

describe('buildDetailHtml — données du backend', () => {
  it('présente les dix-sept champs demandés', () => {
    const html = buildDetailHtml(finding(), NONCE)

    assert.match(html, /SQL Injection/)
    assert.match(html, /Injection/)
    assert.match(html, /Critique/)
    assert.match(html, /92\/100/)
    assert.match(html, /CWE-89/)
    assert.match(html, /A03:2021/)
    assert.match(html, /src\/users\.py/)
    assert.match(html, /ligne 10/)
    assert.match(html, /SELECT \* FROM users/)
    assert.match(html, /concaténée sans échappement/)
    assert.match(html, /lire toute la table/)
    assert.match(html, /Exfiltration de la base/)
    assert.match(html, /Utiliser une requête paramétrée/)
    assert.match(html, /Entrée utilisateur/)
    assert.match(html, /Règle déterministe/)
    assert.match(html, /Ouvert/)
    assert.match(html, new RegExp(FR.detail.fixUnavailable))
  })

  it('annonce « Non disponible. » pour chaque champ vide', () => {
    const html = buildDetailHtml(
      finding({
        cwe: null,
        owasp: null,
        explanation: '',
        why_dangerous: '',
        potential_impact: [],
        recommendations: [],
        risk_factors: [],
        location: {
          line_start: 10,
          line_end: 10,
          column_start: 0,
          column_end: 0,
          snippet: '',
        },
      }),
      NONCE
    )

    const occurrences = html.split(FR.detail.unavailable).length - 1
    // CWE, OWASP, extrait, explication, danger, conséquences,
    // recommandations, facteurs de risque.
    assert.ok(occurrences >= 8, `attendu au moins 8, obtenu ${occurrences}`)
  })

  it("n'invente rien quand le backend ne dit rien", () => {
    const html = buildDetailHtml(
      finding({ explanation: '', why_dangerous: '', recommendations: [] }),
      NONCE
    )

    // Aucun texte de remplissage : uniquement la mention d'absence.
    assert.ok(!/Aucune information/.test(html))
    assert.ok(!/à compléter/i.test(html))
    assert.match(html, new RegExp(FR.detail.unavailable))
  })

  it('traite un champ rempli d’espaces comme absent', () => {
    const html = buildDetailHtml(
      finding({ explanation: '   ', recommendations: ['  ', ''] }),
      NONCE
    )
    assert.ok(!/<p>\s*<\/p>/.test(html))
    assert.match(html, new RegExp(FR.detail.unavailable))
  })

  it('affiche la confiance en pourcentage entier', () => {
    assert.match(buildDetailHtml(finding({ confidence: 0.876 }), NONCE), /88 %/)
  })

  it('affiche un score nul plutôt que de le taire', () => {
    // 0 est une valeur, pas une absence.
    const html = buildDetailHtml(finding({ risk_score: 0 }), NONCE)
    assert.match(html, /0\/100/)
  })

  it('propose le bouton de correction seulement si le backend en offre une', () => {
    const sans = buildDetailHtml(finding({ fix_available: false }), NONCE)
    assert.ok(!sans.includes('id="fix"'))
    assert.match(sans, new RegExp(FR.detail.fixUnavailable))

    const avec = buildDetailHtml(
      finding({ fix_available: true, fix_summary: 'Requête paramétrée' }),
      NONCE
    )
    assert.ok(avec.includes('id="fix"'))
    assert.match(avec, /Requête paramétrée/)
  })

  it('affiche toujours le bouton d’abandon', () => {
    assert.ok(buildDetailHtml(finding(), NONCE).includes('id="dismiss"'))
  })

  it('replie sur la catégorie quand le titre manque', () => {
    const html = buildDetailHtml(finding({ title: '' }), NONCE)
    assert.match(html, /<h1>Injection<\/h1>/)
  })
})

describe('buildDetailHtml — sécurité de la page', () => {
  it("n'interprète jamais le code de l'utilisateur", () => {
    const hostile = finding({
      location: {
        line_start: 1,
        line_end: 1,
        column_start: 0,
        column_end: 10,
        snippet: '<img src=x onerror="alert(1)">',
      },
    })

    const html = buildDetailHtml(hostile, NONCE)

    assert.ok(!html.includes('<img src=x'))
    assert.match(html, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;/)
  })

  it('échappe un titre hostile venu du backend', () => {
    const html = buildDetailHtml(
      finding({ title: '</h1><script>fetch("//x")</script>' }),
      NONCE
    )

    assert.ok(!html.includes('<script>fetch'))
    assert.match(html, /&lt;script&gt;/)
  })

  it('échappe les recommandations et les facteurs de risque', () => {
    const html = buildDetailHtml(
      finding({
        recommendations: ['<b>gras</b>'],
        risk_factors: [{ name: '<i>nom</i>', detail: '<u>detail</u>', weight: 1 }],
      }),
      NONCE
    )

    assert.ok(!html.includes('<b>gras</b>'))
    assert.ok(!html.includes('<i>nom</i>'))
    assert.ok(!html.includes('<u>detail</u>'))
  })

  it("ne laisse pas une gravité inattendue s'échapper de son attribut", () => {
    // Regression : la classe CSS était dérivée du texte reçu. Une valeur
    // forgée par un backend compromis sortait de `class="…"` et injectait
    // ses propres attributs.
    const html = buildDetailHtml(
      finding({ severity: '" onmouseover="alert(1)' as never }),
      NONCE
    )

    assert.ok(!html.includes('onmouseover'))
    assert.match(html, /<span class="badge low"/)
  })

  it('ne produit que les quatre classes de gravité prévues', () => {
    for (const [severity, expected] of [
      ['CRITICAL', 'critical'],
      ['HIGH', 'high'],
      ['MEDIUM', 'medium'],
      ['LOW', 'low'],
      ['INCONNUE', 'low'],
    ] as const) {
      const html = buildDetailHtml(finding({ severity: severity as never }), NONCE)
      assert.match(html, new RegExp(`<span class="badge ${expected}"`))
    }
  })

  it('déclare une CSP stricte, sans unsafe-inline', () => {
    const html = buildDetailHtml(finding(), NONCE)

    assert.match(html, /default-src 'none'/)
    assert.match(html, /object-src 'none'/)
    assert.match(html, /frame-src 'none'/)
    assert.match(html, /base-uri 'none'/)
    assert.match(html, /form-action 'none'/)
    assert.ok(!html.includes('unsafe-inline'))
    assert.ok(!html.includes('unsafe-eval'))
  })

  it('autorise script et style par nonce uniquement', () => {
    const html = buildDetailHtml(finding(), NONCE)

    assert.match(html, new RegExp(`script-src 'nonce-${NONCE}'`))
    assert.match(html, new RegExp(`style-src 'nonce-${NONCE}'`))
    assert.match(html, new RegExp(`<script nonce="${NONCE}">`))
    assert.match(html, new RegExp(`<style nonce="${NONCE}">`))
  })

  it("n'utilise aucun gestionnaire d'événement en ligne", () => {
    // Un attribut `onclick` construit par concaténation serait un point
    // d'injection, et la CSP le refuserait de toute façon.
    const html = buildDetailHtml(finding({ fix_available: true }), NONCE)

    assert.ok(!/\son[a-z]+=/i.test(html.replace(/onerror=&quot;/g, '')))
    assert.match(html, /addEventListener/)
  })

  it('ne référence aucune ressource externe', () => {
    const html = buildDetailHtml(finding(), NONCE)

    assert.ok(!/https?:\/\//.test(html))
    assert.ok(!/<link/.test(html))
    assert.ok(!/src="http/.test(html))
  })

  it('ne transporte ni identifiant technique ni adresse de backend', () => {
    const html = buildDetailHtml(finding(), NONCE)

    assert.ok(!html.includes('127.0.0.1'))
    assert.ok(!html.includes('scan-1'))
    assert.ok(!html.includes('uid-1'))
  })
})
