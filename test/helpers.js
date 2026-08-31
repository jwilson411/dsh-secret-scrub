/**
 * Shared fixtures and stubs. Everything here is offline and synchronous.
 *
 * The fake secrets below are **assembled at runtime from fragments** and never
 * written down whole. That is not decoration: a file holding a contiguous
 * `ghp_` + 36 characters trips GitHub push protection whether or not the token
 * was ever real, and a repository about redacting secrets should not be the
 * thing that leaks one shape-wise. Each fragment set is documented in the
 * README so a reader can see exactly what is being matched.
 *
 * None of these were ever credentials. They are the right *shape* and nothing
 * else — that is the entire point of a pattern redactor, and the entire limit
 * of one.
 */
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/** Fake secrets, one per pattern, each built from fragments. */
export const FIXTURES = Object.freeze({
  GITHUB_PAT: ['ghp_', 'fake', 'x'.repeat(32)].join(''),
  GITHUB_FINE_GRAINED_PAT: [
    'github',
    '_pat_',
    'fake',
    '0'.repeat(18),
    '_',
    'y'.repeat(59),
  ].join(''),
  AWS_ACCESS_KEY_ID: ['AKIA', 'FAKESECRET', '111111'].join(''),
  SLACK_BOT_TOKEN: ['xoxb', '-', '1111111111', '-', '2222222222', '-', 'fake', 'z'.repeat(20)].join(
    '',
  ),
  PEM_PRIVATE_KEY: [
    ['-----BEGIN', 'RSA', 'PRIVATE', 'KEY-----'].join(' '),
    'TEST KEY',
    ['-----END', 'RSA', 'PRIVATE', 'KEY-----'].join(' '),
  ].join('\n'),
  SK_LIVE_TOKEN: ['sk-', 'live', '-', 'fake', 'K'.repeat(24)].join(''),
})

/** The PEM header on its own, for the truncated-body branch of that pattern. */
export const PEM_HEADER_ONLY = ['-----BEGIN', 'RSA', 'PRIVATE', 'KEY-----'].join(' ')

/**
 * Strings that look secret-adjacent but must pass through untouched, so a
 * passing suite means "these shapes and not everything else".
 */
export const NON_SECRETS = Object.freeze([
  'ghp_tooshort',
  ['AKIA', 'lowercase12345678'].join(''),
  ['xoxb', '-', 'nope'].join(''),
  ['sk-', 'short'].join(''),
  'a normal sentence about a private key',
  'https://example.com/path?query=1',
])

/**
 * A context stub exposing only what `apply` is allowed to touch.
 * @returns The stub context and the definitions it recorded.
 */
export function stubContext() {
  const registered = []
  const ctx = {
    tools: {
      register(definition) {
        registered.push(definition)
        return () => {}
      },
    },
  }
  return { ctx, registered }
}

/** The execution context the registry passes to `execute`; unused by these tools. */
export const exec = { signal: new AbortController().signal }

/**
 * A private incident log path under the OS temp directory, removed afterwards.
 *
 * Tests never write into the repository: the log would otherwise be a file full
 * of placeholder lines sitting in the tree the hygiene scan walks.
 * @param t - The running test context, used to register cleanup.
 * @returns An absolute path in a fresh directory.
 */
export function tempLog(t) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-secret-scrub-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return join(dir, 'incidents.jsonl')
}

/**
 * Assert that some text carries no trace of the given secrets.
 *
 * Both the whole secret and its tail are checked: a redactor that replaced a
 * prefix and left the distinctive end of a token behind would pass a
 * whole-string check and still have leaked.
 * @param text - Anything renderable as a string, such as a JSONL file.
 * @param secrets - The fixture values that must be absent.
 * @param what - Named in the failure message.
 */
export function assertNoPreimage(text, secrets, what = 'output') {
  const haystack = typeof text === 'string' ? text : JSON.stringify(text)
  for (const secret of secrets) {
    assert.equal(haystack.includes(secret), false, `${what} contains a secret preimage`)
    const tail = secret.slice(-12)
    assert.equal(haystack.includes(tail), false, `${what} contains the tail of a secret`)
  }
}
