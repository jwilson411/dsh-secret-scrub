/**
 * The plugin seam: that `apply` registers the one tool, that the tool the
 * registry would get behaves the way its declared contract says, and that the
 * package is shaped the way the profile installer expects.
 *
 * `apply` is handed a stub context that records registrations, and the tool is
 * driven through the same `execute` the registry calls, with its result
 * validated against the real `@deepseek-ai/dsh-tools` pinned to `0.1.1-rc.2`.
 * No profile boots and no socket opens.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { ToolArgsError, validateJsonSchemaValue } from '@deepseek-ai/dsh-tools'

import {
  DEFAULT_REPORT_COUNT,
  MAX_REPORT_COUNT,
  PLUGIN_NAME,
  SECRET_SCRUB_REPORT_TOOL_NAME,
  appendIncidents,
  apply,
  clampReportCount,
  createScrubState,
  createSecretScrubReportTool,
  inject,
  name,
  resolveConfig,
  wrapExecute,
} from '../src/index.js'

import { FIXTURES, assertNoPreimage, exec, stubContext, tempLog } from './helpers.js'

/**
 * Synthesize `count` incidents in the log, without going through a tool.
 * @param path - The log path.
 * @param count - How many lines to write.
 */
function seed(path, count) {
  appendIncidents(
    path,
    Array.from({ length: count }, (_, index) => ({
      ts: new Date(index * 1000).toISOString(),
      session: 'seeded',
      tool: 'seed',
      pattern: 'GITHUB_PAT',
      placeholder: `$SECRET_GITHUB_PAT_${index.toString(16).padStart(8, '0')}`,
    })),
  )
}

test('apply registers exactly one tool, named secret_scrub_report', () => {
  const { ctx, registered } = stubContext()

  apply(ctx, { incidentLog: '/tmp/unused-by-this-test.jsonl' })

  assert.equal(registered.length, 1)
  assert.equal(registered[0].name, SECRET_SCRUB_REPORT_TOOL_NAME)
  assert.equal(SECRET_SCRUB_REPORT_TOOL_NAME, 'secret_scrub_report')
  assert.equal(name, 'secret-scrub')
  assert.equal(PLUGIN_NAME, 'dsh-secret-scrub')
  assert.deepEqual(inject, ['tools'])
})

test('apply with no config at all still registers', () => {
  const { ctx, registered } = stubContext()

  apply(ctx)

  assert.equal(registered.length, 1)
  assert.equal(registered[0].name, SECRET_SCRUB_REPORT_TOOL_NAME)
})

test('the registered tool declares one optional integer parameter', () => {
  const { ctx, registered } = stubContext()
  apply(ctx, { incidentLog: '/tmp/unused-by-this-test.jsonl' })
  const [tool] = registered

  assert.equal(tool.parameters.type, 'object')
  assert.equal(tool.parameters.properties.n.type, 'integer')
  assert.deepEqual(tool.parameters.required ?? [], [])
  // The description must not oversell what a pattern redactor can do, and must
  // say plainly that the preimage is gone.
  assert.match(tool.description, /cannot be recovered/)
  assert.match(tool.description, /placeholders and pattern names only/)
})

test('the report returns placeholders and counts, and never a preimage', async (t) => {
  const path = tempLog(t)
  const state = createScrubState({ session: 'session-under-test', salt: 'test-salt-a' })
  // The tool reads both secrets back out of its own source, so each one is
  // redacted once on the way in and once on the way out.
  const wrapped = wrapExecute(
    async () => ({ body: `${FIXTURES.GITHUB_PAT} ${FIXTURES.AWS_ACCESS_KEY_ID}` }),
    state,
    { tool: 'echo', incidentLog: path },
  )
  await wrapped({ a: FIXTURES.GITHUB_PAT, b: FIXTURES.AWS_ACCESS_KEY_ID }, exec)

  const tool = createSecretScrubReportTool(resolveConfig({ incidentLog: path }))
  const value = await tool.execute({}, exec)

  assert.deepEqual(validateJsonSchemaValue(tool.output.schema, value, tool.name), [])
  assert.equal(value.plugin, PLUGIN_NAME)
  assert.equal(value.log, path)
  // Two secrets, each redacted on the way in and again on the way out.
  assert.equal(value.total, 4)
  assert.deepEqual(value.counts, [
    { pattern: 'AWS_ACCESS_KEY_ID', count: 2 },
    { pattern: 'GITHUB_PAT', count: 2 },
  ])
  for (const incident of value.incidents) {
    assert.equal(incident.session, 'session-under-test')
    assert.equal(incident.tool, 'echo')
    assert.match(incident.placeholder, /^\$SECRET_[A-Z_]+_[0-9a-f]{8}$/)
  }
  assertNoPreimage(JSON.stringify(value), Object.values(FIXTURES), 'the report tool')

  assert.deepEqual(tool.output.render({}, value), [
    {
      type: 'text',
      text: 'secret-scrub: 4 incident(s) — AWS_ACCESS_KEY_ID×2, GITHUB_PAT×2',
    },
  ])
})

test('an empty log reports nothing rather than failing', async (t) => {
  const path = tempLog(t)
  const tool = createSecretScrubReportTool({ incidentLog: path })

  const value = await tool.execute({}, exec)

  assert.deepEqual(value.incidents, [])
  assert.deepEqual(value.counts, [])
  assert.equal(value.total, 0)
  assert.deepEqual(tool.output.render({}, value), [
    { type: 'text', text: 'secret-scrub: no incidents recorded' },
  ])
})

test('the report defaults to the recent window and is capped', async (t) => {
  const path = tempLog(t)
  seed(path, MAX_REPORT_COUNT + 50)
  const tool = createSecretScrubReportTool({ incidentLog: path })

  const byDefault = await tool.execute({}, exec)
  const asked = await tool.execute({ n: 3 }, exec)
  const greedy = await tool.execute({ n: 100000 }, exec)

  assert.equal(byDefault.total, DEFAULT_REPORT_COUNT)
  assert.equal(asked.total, 3)
  assert.equal(greedy.total, MAX_REPORT_COUNT)
  // The window is the tail: the newest line is the last one returned.
  const newest = `$SECRET_GITHUB_PAT_${(MAX_REPORT_COUNT + 49).toString(16).padStart(8, '0')}`
  assert.equal(asked.incidents.at(-1).placeholder, newest)
})

test('clampReportCount keeps a request inside the window', () => {
  assert.equal(clampReportCount(undefined), DEFAULT_REPORT_COUNT)
  assert.equal(clampReportCount(Number.NaN), DEFAULT_REPORT_COUNT)
  assert.equal(clampReportCount(0), 1)
  assert.equal(clampReportCount(-5), 1)
  assert.equal(clampReportCount(7), 7)
  assert.equal(clampReportCount(MAX_REPORT_COUNT + 1), MAX_REPORT_COUNT)
})

test('invalid arguments fail loudly instead of executing', async (t) => {
  const path = tempLog(t)
  const tool = createSecretScrubReportTool({ incidentLog: path })

  for (const args of [{ n: 'twenty' }, { n: 1.5 }, { n: null }, null, [], 'twenty']) {
    await assert.rejects(
      () => tool.execute(args, exec),
      (error) => {
        assert.ok(error instanceof ToolArgsError)
        assert.ok(error.violations.length > 0)
        return true
      },
      `expected ToolArgsError for ${JSON.stringify(args) ?? String(args)}`,
    )
  }
})

test('config is the patch row, then the environment, then the default', () => {
  assert.deepEqual(resolveConfig({ incidentLog: '/tmp/a.jsonl' }, {}), {
    incidentLog: '/tmp/a.jsonl',
  })
  assert.deepEqual(resolveConfig({}, { DSH_SECRET_SCRUB_LOG: '/tmp/b.jsonl' }), {
    incidentLog: '/tmp/b.jsonl',
  })
  assert.deepEqual(resolveConfig({}, {}), { incidentLog: '.dsh-secret-scrub.jsonl' })
})

test('the manifest declares the bundle patch the profile installer looks for', () => {
  const manifestPath = fileURLToPath(new URL('../package.json', import.meta.url))
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))

  assert.equal(manifest.dsh.bundle.patch, './cordis.patch.yml')
  assert.equal(manifest.name, PLUGIN_NAME)
  assert.equal(manifest.type, 'module')
  assert.equal(manifest.devDependencies['@deepseek-ai/dsh-tools'], '0.1.1-rc.2')
  assert.equal(manifest.peerDependencies['@deepseek-ai/dsh-tools'], '^0.1.1-rc.2')
  assert.equal(manifest.peerDependencies['@deepseek-ai/cordis'], '^4.0.1')
  assert.equal(manifest.engines.node, '>=22.14.0')
  assert.equal(manifest.scripts.test, 'node --test "test/**/*.test.js"')
  for (const keyword of ['dsh-plugin', 'deepseek-harness']) {
    assert.ok(manifest.keywords.includes(keyword), `missing keyword ${keyword}`)
  }

  const patchPath = fileURLToPath(new URL('../cordis.patch.yml', import.meta.url))
  const patch = readFileSync(patchPath, 'utf8')
  assert.match(patch, /^- insert:$/m)
  assert.match(patch, /^ {4}- id: secret-scrub$/m)
  assert.match(patch, new RegExp(`name: ${manifest.name}$`, 'm'))
  // The documented config key is the one resolveConfig actually reads.
  assert.match(patch, /incidentLog/)
  assert.match(patch, /DSH_SECRET_SCRUB_LOG/)
})
