/**
 * The library: the pattern table, the placeholder function, and the walk.
 *
 * Every fake secret here is assembled from fragments in `helpers.js`, so the
 * committed tree never holds a whole token. Nothing in this file touches the
 * network, the clock, or the filesystem.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  PATTERNS,
  PLACEHOLDER_PATTERN,
  createScrubState,
  placeholderFor,
  scrub,
} from '../src/scrub.js'

import { FIXTURES, NON_SECRETS, PEM_HEADER_ONLY, assertNoPreimage } from './helpers.js'

/** A state with a fixed salt, so a failure is reproducible. */
function state(salt = 'test-salt-a') {
  return createScrubState({ session: 'session-under-test', salt })
}

test('the table names, versions, and dates every pattern', () => {
  const names = PATTERNS.map((pattern) => pattern.name)

  assert.deepEqual(names, [
    'GITHUB_PAT',
    'GITHUB_FINE_GRAINED_PAT',
    'AWS_ACCESS_KEY_ID',
    'SLACK_BOT_TOKEN',
    'PEM_PRIVATE_KEY',
    'SK_LIVE_TOKEN',
  ])
  assert.equal(new Set(names).size, names.length)

  for (const pattern of PATTERNS) {
    // The name is embedded in every placeholder, so it has to survive the
    // anchored placeholder check.
    assert.match(pattern.name, /^[A-Z][A-Z0-9_]*$/)
    assert.equal(Number.isInteger(pattern.version) && pattern.version >= 1, true)
    assert.equal(pattern.since, '2026-08-31')
    assert.equal(pattern.regex.global, true)
    assert.ok(pattern.description.length > 0)
  }
})

test('every documented pattern redacts its fixture, leaving a shaped placeholder', () => {
  for (const [name, secret] of Object.entries(FIXTURES)) {
    const { value, findings } = scrub(`before ${secret} after`, state())

    assert.deepEqual(
      findings.map((finding) => finding.pattern),
      [name],
      `${name} did not match its own fixture`,
    )
    const [{ placeholder }] = findings
    assert.match(placeholder, PLACEHOLDER_PATTERN)
    assert.match(placeholder, new RegExp(`^\\$SECRET_${name}_[0-9a-f]{8}$`))
    assert.equal(value, `before ${placeholder} after`)
    assertNoPreimage(value, [secret], name)
  }
})

test('a PEM block collapses whole, so the key material goes with the header', () => {
  const { value, findings } = scrub(FIXTURES.PEM_PRIVATE_KEY, state())

  assert.equal(findings.length, 1)
  assert.equal(value, findings[0].placeholder)
  assert.equal(value.includes('TEST KEY'), false)
})

test('a PEM header with no body still matches', () => {
  const { value, findings } = scrub(`${PEM_HEADER_ONLY}\ntruncated`, state())

  assert.equal(findings.length, 1)
  assert.equal(findings[0].pattern, 'PEM_PRIVATE_KEY')
  assert.equal(value, `${findings[0].placeholder}\ntruncated`)
})

test('near-misses pass through untouched', () => {
  for (const text of NON_SECRETS) {
    const { value, findings } = scrub(text, state())

    assert.equal(value, text, `${text} was redacted`)
    assert.deepEqual(findings, [])
  }
})

test('the same bytes redact to the same placeholder within one state', () => {
  const shared = state()
  const secret = FIXTURES.AWS_ACCESS_KEY_ID

  const first = scrub(`a ${secret} b ${secret}`, shared)
  const second = scrub({ nested: [secret] }, shared)

  // Twice in one string, and again in a later call on a different container.
  assert.equal(first.findings.length, 1)
  assert.equal(first.findings[0].count, 2)
  assert.equal(second.findings[0].placeholder, first.findings[0].placeholder)
  assert.equal(
    first.value,
    `a ${first.findings[0].placeholder} b ${first.findings[0].placeholder}`,
  )
})

test('different secrets redact to different placeholders', () => {
  const shared = state()
  const other = ['AKIA', 'FAKESECRET', '222222'].join('')

  const { findings } = scrub([FIXTURES.AWS_ACCESS_KEY_ID, other], shared)

  assert.equal(findings.length, 2)
  assert.notEqual(findings[0].placeholder, findings[1].placeholder)
  assert.equal(findings[0].pattern, findings[1].pattern)
})

test('a different session may redact the same bytes differently: the digest is salted', () => {
  const secret = FIXTURES.GITHUB_PAT

  const a = scrub(secret, state('test-salt-a')).value
  const b = scrub(secret, state('test-salt-b')).value

  assert.notEqual(a, b)
  // Both are still well-formed placeholders for the same pattern.
  for (const value of [a, b]) assert.match(value, /^\$SECRET_GITHUB_PAT_[0-9a-f]{8}$/)
})

test('the walk reaches strings in nested objects, arrays, and keys', () => {
  const shared = state()
  const secret = FIXTURES.SLACK_BOT_TOKEN
  const input = {
    headers: { authorization: `Bearer ${secret}` },
    items: [{ note: 'clean' }, [`${secret}`, 7, null, true]],
    [secret]: 'keyed by a token',
  }

  const { value, findings } = scrub(input, shared)
  const { placeholder } = findings[0]

  assert.equal(findings.length, 1)
  assert.equal(findings[0].count, 3)
  assert.equal(value.headers.authorization, `Bearer ${placeholder}`)
  assert.deepEqual(value.items, [{ note: 'clean' }, [placeholder, 7, null, true]])
  assert.equal(value[placeholder], 'keyed by a token')
  assertNoPreimage(JSON.stringify(value), [secret], 'walk output')
})

test('the walk copies rather than mutates, and passes non-plain values through', () => {
  const shared = state()
  const when = new Date(0)
  const input = { token: FIXTURES.SK_LIVE_TOKEN, when, count: 3 }

  const { value } = scrub(input, shared)

  assert.equal(input.token, FIXTURES.SK_LIVE_TOKEN, 'the caller copy was mutated')
  assert.notEqual(value, input)
  // A Date is handed back as-is rather than flattened into something that
  // resembles one.
  assert.equal(value.when, when)
  assert.equal(value.count, 3)
})

test('a cyclic structure is redacted rather than hung on', () => {
  const shared = state()
  const input = { token: FIXTURES.GITHUB_FINE_GRAINED_PAT }
  input.self = input

  const { value, findings } = scrub(input, shared)

  assert.equal(value.token, findings[0].placeholder)
  assert.equal(value.self, value)
})

test('scalars and empty containers survive the walk', () => {
  const shared = state()

  for (const input of [null, undefined, 7, true, '', [], {}]) {
    const { value, findings } = scrub(input, shared)
    assert.deepEqual(value, input)
    assert.deepEqual(findings, [])
  }
})

test('placeholderFor is stable, salted, and keeps nothing of the preimage', () => {
  const shared = state()
  const secret = FIXTURES.SK_LIVE_TOKEN

  const placeholder = placeholderFor('SK_LIVE_TOKEN', secret, shared)

  assert.equal(placeholderFor('SK_LIVE_TOKEN', secret, shared), placeholder)
  assert.notEqual(placeholderFor('SK_LIVE_TOKEN', secret, state('other-salt')), placeholder)
  assertNoPreimage(placeholder, [secret], 'placeholder')
  // The memo table maps secret to placeholder and holds no reverse direction.
  assert.equal([...shared.placeholders.values()].includes(secret), false)
})
