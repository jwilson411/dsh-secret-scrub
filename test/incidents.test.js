/**
 * The wrapper and the log: that a wrapped `execute` is scrubbed in **both**
 * directions, and that what lands on disk names the redaction without carrying
 * the thing redacted.
 *
 * The log is written into a fresh directory under the OS temp directory, never
 * into the repository. No network, no registry, no profile.
 */
import assert from 'node:assert/strict'
import { appendFileSync, readFileSync } from 'node:fs'
import { test } from 'node:test'

import {
  DEFAULT_INCIDENT_LOG,
  INCIDENT_LOG_ENV,
  appendIncidents,
  countByPattern,
  createScrubState,
  readIncidents,
  resolveIncidentLog,
  scrubToolArgs,
  scrubToolResult,
  toIncidents,
  wrapExecute,
} from '../src/scrub.js'

import { FIXTURES, assertNoPreimage, exec, tempLog } from './helpers.js'

/** Every fixture value, for the "none of these appear anywhere" assertions. */
const ALL_SECRETS = Object.values(FIXTURES)

/** A state with a fixed salt and session, so a failure is reproducible. */
function state() {
  return createScrubState({ session: 'session-under-test', salt: 'test-salt-a' })
}

/**
 * Every line of the log, parsed.
 * @param path - The log path.
 * @returns The parsed objects, in write order.
 */
function lines(path) {
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((line) => line !== '')
    .map((line) => JSON.parse(line))
}

test('a wrapped execute scrubs arguments on the way in', async (t) => {
  const path = tempLog(t)
  const seen = []
  const wrapped = wrapExecute(
    async (args) => {
      seen.push(args)
      return { ok: true }
    },
    state(),
    { tool: 'http_get', incidentLog: path },
  )

  await wrapped({ headers: { authorization: FIXTURES.GITHUB_PAT } }, exec)

  // The tool itself ran on the redacted arguments: the secret stopped here,
  // not at the boundary of the transcript.
  assert.equal(seen.length, 1)
  assert.match(seen[0].headers.authorization, /^\$SECRET_GITHUB_PAT_[0-9a-f]{8}$/)
  assertNoPreimage(JSON.stringify(seen[0]), [FIXTURES.GITHUB_PAT], 'inbound arguments')
})

test('a wrapped execute scrubs the result on the way out', async (t) => {
  const path = tempLog(t)
  const wrapped = wrapExecute(
    async () => ({ body: `key=${FIXTURES.AWS_ACCESS_KEY_ID}`, nested: [FIXTURES.SK_LIVE_TOKEN] }),
    state(),
    { tool: 'read_file', incidentLog: path },
  )

  const result = await wrapped({ path: 'creds.txt' }, exec)

  assert.match(result.body, /^key=\$SECRET_AWS_ACCESS_KEY_ID_[0-9a-f]{8}$/)
  assert.match(result.nested[0], /^\$SECRET_SK_LIVE_TOKEN_[0-9a-f]{8}$/)
  assertNoPreimage(JSON.stringify(result), ALL_SECRETS, 'outbound result')
})

test('one placeholder spans both directions of one session', async (t) => {
  const path = tempLog(t)
  const shared = state()
  // The tool produces the secret itself — reading it back off disk, say —
  // rather than echoing the argument, so both directions really carry it.
  const wrapped = wrapExecute(async () => ({ found: FIXTURES.SLACK_BOT_TOKEN }), shared, {
    tool: 'read_file',
    incidentLog: path,
  })

  const result = await wrapped({ token: FIXTURES.SLACK_BOT_TOKEN }, exec)
  const written = lines(path)

  // Two incidents — one in, one out — naming the same secret with the same
  // placeholder, so a reader can see it was the same token on both sides.
  assert.equal(written.length, 2)
  assert.equal(written[0].placeholder, written[1].placeholder)
  assert.equal(result.found, written[0].placeholder)
})

test('the JSONL log carries exactly the five public fields, and no preimage', async (t) => {
  const path = tempLog(t)
  const wrapped = wrapExecute(async () => FIXTURES.PEM_PRIVATE_KEY, state(), {
    tool: 'cat',
    incidentLog: path,
  })

  await wrapped({ blob: FIXTURES.GITHUB_FINE_GRAINED_PAT }, exec)

  const raw = readFileSync(path, 'utf8')
  assertNoPreimage(raw, ALL_SECRETS, 'the incident log')
  assert.equal(raw.endsWith('\n'), true)

  const written = lines(path)
  assert.equal(written.length, 2)
  for (const incident of written) {
    assert.deepEqual(Object.keys(incident).sort(), [
      'pattern',
      'placeholder',
      'session',
      'tool',
      'ts',
    ])
    assert.equal(incident.session, 'session-under-test')
    assert.equal(incident.tool, 'cat')
    assert.equal(new Date(incident.ts).toISOString(), incident.ts)
  }
  assert.deepEqual(
    written.map((incident) => incident.pattern),
    ['GITHUB_FINE_GRAINED_PAT', 'PEM_PRIVATE_KEY'],
  )
})

test('the log is append-only across calls', async (t) => {
  const path = tempLog(t)
  const shared = state()
  const wrapped = wrapExecute(async (args) => args, shared, { tool: 'echo', incidentLog: path })

  const first = await wrapped({ token: FIXTURES.GITHUB_PAT }, exec)
  const afterFirst = lines(path)
  await wrapped({ token: FIXTURES.AWS_ACCESS_KEY_ID }, exec)
  const afterSecond = lines(path)

  // One line per call, not two: this tool echoes its arguments, and by the time
  // it does they are already a placeholder. A redacted echo is not a second
  // sighting of the secret and is not logged as one.
  assert.match(first.token, /^\$SECRET_GITHUB_PAT_[0-9a-f]{8}$/)
  assert.equal(afterFirst.length, 1)
  assert.equal(afterSecond.length, 2)
  // The earlier line is still there, byte for byte.
  assert.deepEqual(afterSecond.slice(0, 1), afterFirst)
  assert.deepEqual(
    afterSecond.map((incident) => incident.pattern),
    ['GITHUB_PAT', 'AWS_ACCESS_KEY_ID'],
  )
})

test('a clean call writes nothing at all', async (t) => {
  const path = tempLog(t)
  const wrapped = wrapExecute(async () => ({ ok: true }), state(), {
    tool: 'ping',
    incidentLog: path,
  })

  await wrapped({ host: 'example.com' }, exec)

  // No secrets, no file: an empty log is the normal case and should not be
  // created just to hold nothing.
  assert.deepEqual(readIncidents(path), [])
})

test('a rejecting tool still has its arguments scrubbed and logged', async (t) => {
  const path = tempLog(t)
  const wrapped = wrapExecute(
    async () => {
      throw new Error('upstream failed')
    },
    state(),
    { tool: 'flaky', incidentLog: path },
  )

  await assert.rejects(() => wrapped({ token: FIXTURES.GITHUB_PAT }, exec), /upstream failed/)

  const written = lines(path)
  assert.equal(written.length, 1)
  assert.equal(written[0].pattern, 'GITHUB_PAT')
  assertNoPreimage(readFileSync(path, 'utf8'), ALL_SECRETS, 'the incident log')
})

test('scrubToolArgs and scrubToolResult carry the session onto their incidents', () => {
  const shared = state()

  const inbound = scrubToolArgs({ token: FIXTURES.GITHUB_PAT }, shared, { tool: 'grep' })
  const outbound = scrubToolResult([FIXTURES.GITHUB_PAT], shared, { tool: 'grep' })

  for (const { incidents } of [inbound, outbound]) {
    assert.equal(incidents.length, 1)
    assert.equal(incidents[0].session, 'session-under-test')
    assert.equal(incidents[0].tool, 'grep')
  }
  assert.equal(inbound.incidents[0].placeholder, outbound.incidents[0].placeholder)
  assert.equal(inbound.args.token, outbound.result[0])
})

test('an incident holds only the five fields, whatever the finding held', () => {
  const incidents = toIncidents([{ pattern: 'GITHUB_PAT', placeholder: '$SECRET_GITHUB_PAT_0011aabb', count: 4 }], {
    session: 's',
    tool: 't',
    ts: '2026-08-31T00:00:00.000Z',
  })

  assert.deepEqual(incidents, [
    {
      ts: '2026-08-31T00:00:00.000Z',
      session: 's',
      tool: 't',
      pattern: 'GITHUB_PAT',
      placeholder: '$SECRET_GITHUB_PAT_0011aabb',
    },
  ])
})

test('reading the log returns the tail, oldest first, and skips junk', (t) => {
  const path = tempLog(t)
  const incidents = Array.from({ length: 5 }, (_, index) => ({
    ts: `2026-08-31T00:00:0${index}.000Z`,
    session: 's',
    tool: 't',
    pattern: 'GITHUB_PAT',
    placeholder: `$SECRET_GITHUB_PAT_0000000${index}`,
  }))

  assert.equal(appendIncidents(path, incidents), 5)
  appendFileSync(path, 'not json at all\n\n', 'utf8')

  const tail = readIncidents(path, 2)
  assert.deepEqual(
    tail.map((incident) => incident.placeholder),
    ['$SECRET_GITHUB_PAT_00000003', '$SECRET_GITHUB_PAT_00000004'],
  )
  assert.equal(readIncidents(path, 99).length, 5)
  assert.deepEqual(readIncidents(path, 0), [])
  assert.deepEqual(countByPattern(readIncidents(path, 99)), [{ pattern: 'GITHUB_PAT', count: 5 }])
})

test('a tampered line cannot smuggle a preimage back out through the reader', (t) => {
  const path = tempLog(t)

  appendFileSync(
    path,
    `${JSON.stringify({
      ts: '2026-08-31T00:00:00.000Z',
      session: 's',
      tool: 't',
      pattern: 'GITHUB_PAT',
      placeholder: '$SECRET_GITHUB_PAT_00000001',
      preimage: FIXTURES.GITHUB_PAT,
    })}\n${JSON.stringify({
      ts: '2026-08-31T00:00:01.000Z',
      session: 's',
      tool: 't',
      pattern: 'GITHUB_PAT',
      // Not placeholder-shaped: the whole record is dropped rather than echoed.
      placeholder: FIXTURES.GITHUB_PAT,
    })}\n`,
    'utf8',
  )

  const read = readIncidents(path, 10)

  assert.equal(read.length, 1)
  assert.deepEqual(Object.keys(read[0]).sort(), ['pattern', 'placeholder', 'session', 'tool', 'ts'])
  assertNoPreimage(JSON.stringify(read), [FIXTURES.GITHUB_PAT], 'the reader')
})

test('a missing log reads as no incidents rather than throwing', (t) => {
  const path = tempLog(t)

  assert.deepEqual(readIncidents(path), [])
  assert.deepEqual(countByPattern([]), [])
})

test('counts are ordered by frequency, then by name', () => {
  const rows = countByPattern([
    { pattern: 'SK_LIVE_TOKEN' },
    { pattern: 'GITHUB_PAT' },
    { pattern: 'SK_LIVE_TOKEN' },
    { pattern: 'AWS_ACCESS_KEY_ID' },
  ])

  assert.deepEqual(rows, [
    { pattern: 'SK_LIVE_TOKEN', count: 2 },
    { pattern: 'AWS_ACCESS_KEY_ID', count: 1 },
    { pattern: 'GITHUB_PAT', count: 1 },
  ])
})

test('the log path is config, then environment, then the default', () => {
  assert.equal(resolveIncidentLog({}, {}), DEFAULT_INCIDENT_LOG)
  assert.equal(resolveIncidentLog({}, { [INCIDENT_LOG_ENV]: '/tmp/from-env.jsonl' }), '/tmp/from-env.jsonl')
  assert.equal(
    resolveIncidentLog({ incidentLog: '/tmp/from-config.jsonl' }, { [INCIDENT_LOG_ENV]: '/tmp/from-env.jsonl' }),
    '/tmp/from-config.jsonl',
  )
  // A blank string is not a stated intent; it falls through.
  assert.equal(resolveIncidentLog({ incidentLog: '   ' }, {}), DEFAULT_INCIDENT_LOG)
})
