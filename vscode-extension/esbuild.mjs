/**
 * Build de l'extension : un seul fichier CommonJS dans dist/.
 *
 * `vscode` est marque "external" : ce module est fourni par l'hote au
 * moment de l'execution, il ne doit jamais etre embarque.
 */
import { readdir } from 'node:fs/promises'

import { build, context } from 'esbuild'

const production = process.argv.includes('--production')
const watch = process.argv.includes('--watch')
const tests = process.argv.includes('--tests')

/** @type {import('esbuild').BuildOptions} */
const options = {
  entryPoints: ['src/extension.ts'],
  bundle: true,
  outfile: 'dist/extension.js',
  format: 'cjs',
  platform: 'node',
  // VS Code 1.85 embarque Node 18.
  target: 'node18',
  external: ['vscode'],
  sourcemap: !production,
  minify: production,
  logLevel: 'info',
}

// Les tests portent sur les modules sans dependance a `vscode` : ils
// tournent avec le lanceur natif de Node, sans dependance supplementaire.
if (tests) {
  const entryPoints = (await readdir('test'))
    .filter((name) => name.endsWith('.test.ts'))
    .map((name) => `test/${name}`)

  await build({
    entryPoints,
    bundle: true,
    outdir: 'out-test',
    outExtension: { '.js': '.cjs' },
    format: 'cjs',
    platform: 'node',
    target: 'node18',
    external: ['vscode'],
    sourcemap: true,
    logLevel: 'info',
  })
  console.log('[wazuh-security] tests compiles dans out-test/')
} else if (watch) {
  const ctx = await context(options)
  await ctx.watch()
  console.log('[wazuh-security] surveillance des sources active')
} else {
  await build(options)
  // Controle CI/CD (phase 8) : meme code que l'extension, sans `vscode`.
  // Un second paquet plutot qu'un second projet : aucun moteur duplique.
  await build({
    ...options,
    entryPoints: ['src/cli/ciCheck.ts'],
    outfile: 'dist/ci-check.js',
    banner: { js: '#!/usr/bin/env node' },
  })
  console.log(`[wazuh-security] build ${production ? 'production' : 'developpement'} termine`)
}
