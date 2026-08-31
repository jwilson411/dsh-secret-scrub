/**
 * Repository hygiene, asserted rather than promised.
 *
 * A package about redacting secrets has an obvious way to embarrass itself:
 * ship one. So the redactor is pointed at its own tree. Every pattern in
 * `PATTERNS` is run over every checked-in text file, and a hit fails the suite
 * — which is why the fake secrets in `helpers.js` are assembled from fragments
 * at runtime rather than written down whole.
 *
 * The other two claims checked here are that the tree carries no machine names,
 * mount paths, or credential-variable names from wherever it was written, and
 * that the shipped source opens nothing: no socket, no fetch, no subprocess. A
 * redactor that quietly phoned home would falsify the whole design, so the
 * check is a test and not a comment.
 *
 * The forbidden literals are assembled from fragments so that this file does
 * not itself trip the scan it performs.
 */
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { extname, join, relative, sep } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { PATTERNS } from '../src/scrub.js'

/** The package root, walked below. */
const ROOT = fileURLToPath(new URL('..', import.meta.url))

/** Directories never worth scanning: not ours, or not text. */
const SKIP_DIRS = new Set(['node_modules', '.git'])

/** Extensions with no text worth scanning. */
const BINARY_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2'])

/**
 * Every checked-in text file, repo-relative.
 * @returns Paths relative to the package root, in directory order.
 */
function repoFiles() {
  return readdirSync(ROOT, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => relative(ROOT, join(entry.parentPath ?? entry.path, entry.name)))
    .filter((path) => !path.split(sep).some((segment) => SKIP_DIRS.has(segment)))
    .filter((path) => !BINARY_EXTENSIONS.has(extname(path)))
}

/**
 * Read a repo file as text.
 * @param path - A repo-relative path.
 * @returns Its contents.
 */
function readRepoFile(path) {
  return readFileSync(join(ROOT, path), 'utf8')
}

/**
 * The literals that must not appear anywhere in the tree, each built from
 * fragments so this file is not its own counterexample.
 */
const FORBIDDEN = [
  { what: 'a private machine name', pattern: new RegExp(['def', 'iant'].join(''), 'i') },
  { what: 'a host-local mount path', pattern: /\/mnt\/[a-z]/i },
  { what: 'a CI token variable', pattern: new RegExp(['GITHUB', 'TOKEN'].join('_')) },
  { what: 'a provider key variable', pattern: new RegExp(['ANTHROPIC', 'API', 'KEY'].join('_')) },
  { what: 'a provider key variable', pattern: new RegExp(['OPENAI', 'API', 'KEY'].join('_')) },
  { what: 'a bearer token literal', pattern: /\bBearer [A-Za-z0-9._-]{20,}/ },
]

test('the tree carries no machine names, mount paths, or credential variables', () => {
  const offences = []

  for (const path of repoFiles()) {
    const text = readRepoFile(path)
    for (const { what, pattern } of FORBIDDEN) {
      const hit = pattern.exec(text)
      if (hit !== null) offences.push(`${path}: ${what} (${hit[0].slice(0, 24)})`)
    }
  }

  assert.deepEqual(offences, [])
})

test('the redactor finds nothing to redact in its own tree', () => {
  // Every fake secret this suite uses is assembled at runtime from fragments,
  // so no committed file — src, tests, README, or lockfile — holds a whole
  // token of any shape this package knows. Push protection has nothing to
  // reject, and the src/ tree in particular is clean by the same check.
  const offences = []

  for (const path of repoFiles()) {
    const text = readRepoFile(path)
    for (const pattern of PATTERNS) {
      // The table's regexes are global; `exec` on a shared global regex would
      // carry lastIndex between files, so match through a fresh copy.
      const scanner = new RegExp(pattern.regex.source, 'g')
      const hit = scanner.exec(text)
      if (hit !== null) offences.push(`${path}: ${pattern.name}`)
    }
  }

  assert.deepEqual(offences, [])
})

test('the scan actually covers the files it claims to', () => {
  const files = repoFiles()

  for (const expected of [
    'package.json',
    'package-lock.json',
    'cordis.patch.yml',
    'README.md',
    'LICENSE',
    join('.github', 'workflows', 'ci.yml'),
    join('src', 'index.js'),
    join('src', 'scrub.js'),
    join('test', 'helpers.js'),
  ]) {
    assert.ok(files.includes(expected), `hygiene scan missed ${expected}`)
  }
  assert.equal(
    files.some((path) => path.startsWith('node_modules')),
    false,
  )
})

test('the shipped source opens nothing: no socket, no fetch, no subprocess', () => {
  // This package reads and appends one local file and hashes bytes. Those are
  // the ways it could acquire an egress path of its own — including one that
  // shipped a redaction log somewhere off the box.
  const banned = [
    /\bfetch\s*\(/,
    /\bXMLHttpRequest\b/,
    /\bnode:(dns|net|tls|http|https|dgram|child_process|worker_threads)\b/,
    /\brequire\s*\(/,
    /\bimport\s*\(/,
  ]

  for (const path of repoFiles().filter((file) => file.startsWith(`src${sep}`))) {
    const text = readRepoFile(path)
    for (const pattern of banned) {
      assert.equal(pattern.test(text), false, `${path} matches ${pattern}`)
    }
  }
})

test('the shipped source imports only the pinned tools package, node builtins it needs, and itself', () => {
  const allowed = new Set(['@deepseek-ai/dsh-tools', 'node:crypto', 'node:fs'])
  const specifiers = []

  for (const path of repoFiles().filter((file) => file.startsWith(`src${sep}`))) {
    const text = readRepoFile(path)
    for (const match of text.matchAll(/^\s*(?:import|export)[^'"\n]*from\s*'([^']+)'/gm)) {
      specifiers.push(match[1])
    }
  }

  assert.ok(specifiers.length > 0)
  for (const specifier of specifiers) {
    assert.ok(
      allowed.has(specifier) || specifier.startsWith('./'),
      `unexpected import ${specifier}`,
    )
  }
})

test('CI needs no credentials', () => {
  const workflow = readRepoFile(join('.github', 'workflows', 'ci.yml'))

  assert.match(workflow, /contents: read/)
  assert.match(workflow, /npm ci/)
  assert.match(workflow, /npm test/)
  assert.match(workflow, /'22\.x', '24\.x'/)
  assert.equal(/secrets\./.test(workflow), false)
})

test('the README documents every pattern by name, version, and date', () => {
  const readme = readRepoFile('README.md')

  for (const pattern of PATTERNS) {
    assert.match(readme, new RegExp(`\`${pattern.name}\``), `README omits ${pattern.name}`)
  }
  assert.match(readme, /2026-08-31/)
  // The headline disclaimer is load-bearing: this is shape matching.
  assert.match(readme, /not a secret manager/i)
})
