/**
 * dsh-secret-scrub — a DeepSeek Harness function plugin that redacts known
 * secret shapes **on the way in and out of tool execution**, and records what
 * it redacted without recording what it redacted it from.
 *
 * The library API is {@link wrapExecute}: wrap a tool's `execute` and the
 * arguments are scrubbed before the tool runs, the result is scrubbed before it
 * returns, and each distinct secret becomes one append-only JSONL line naming
 * the pattern and the placeholder — never the bytes. {@link scrub} is the same
 * walk, exposed on its own for a host that wants to redact something else.
 *
 * **This is pattern redaction, not a secret manager.** It matches shapes it has
 * been taught. It does not hold, rotate, issue, or verify anything. See the
 * README for the full list of what it is not.
 *
 * The pinned DSH release candidate, `0.1.1-rc.2`, exposes no tool-execute
 * middleware seam, so the plugin does not invent one: it registers exactly one
 * model-facing tool, `secret_scrub_report`, against the `tools` service and
 * exports the wrapper for a host to apply at its own call site. Registration
 * happens inside `apply` so the Cordis fiber owns the effect: stopping,
 * updating, or reloading the plugin unregisters the tool with no bookkeeping
 * here. Named exports preserve the loader's injection metadata.
 *
 * @module dsh-secret-scrub
 */
import { defineTool } from '@deepseek-ai/dsh-tools'

import {
  DEFAULT_REPORT_COUNT,
  MAX_REPORT_COUNT,
  PLUGIN_NAME,
  countByPattern,
  readIncidents,
  resolveIncidentLog,
} from './scrub.js'

export {
  DEFAULT_INCIDENT_LOG,
  DEFAULT_REPORT_COUNT,
  INCIDENT_LOG_ENV,
  MAX_REPORT_COUNT,
  PATTERNS,
  PLACEHOLDER_PATTERN,
  PLUGIN_NAME,
  appendIncidents,
  countByPattern,
  createScrubState,
  placeholderFor,
  readIncidents,
  resolveIncidentLog,
  scrub,
  scrubToolArgs,
  scrubToolResult,
  toIncidents,
  wrapExecute,
} from './scrub.js'

/** The one model-facing tool name this plugin owns. */
export const SECRET_SCRUB_REPORT_TOOL_NAME = 'secret_scrub_report'

/** Cordis plugin name, used in loader diagnostics and the runtime plugin tree. */
export const name = 'secret-scrub'

/**
 * `tools` is a hard dependency: with no registry there is nothing to register
 * the report against, so the plugin waits rather than degrading.
 */
export const inject = ['tools']

/**
 * Resolve the plugin's effective settings.
 *
 * Precedence is patch config, then environment, then default — the patch row is
 * the deployment's stated intent, so it wins over an ambient variable.
 * @param config - The `config` block of this plugin's row in the composed patch.
 * @param env - Environment to read, injectable for tests.
 * @returns `{ incidentLog }`.
 */
export function resolveConfig(config = {}, env = process.env) {
  return { incidentLog: resolveIncidentLog(config, env) }
}

/**
 * Clamp a requested report size into the allowed window.
 *
 * A model asking for everything gets {@link MAX_REPORT_COUNT}, not everything:
 * the log grows without bound and a report is a glance at the tail, not an
 * export.
 * @param n - The `n` argument, if the model supplied one.
 * @returns A count between 1 and the cap.
 */
export function clampReportCount(n) {
  if (typeof n !== 'number' || !Number.isFinite(n)) return DEFAULT_REPORT_COUNT
  return Math.min(Math.max(1, Math.trunc(n)), MAX_REPORT_COUNT)
}

/**
 * Build the `secret_scrub_report` tool definition.
 *
 * Kept as a factory rather than a module-scope constant so nothing is
 * constructed at import time and each `apply` owns a definition bound to its
 * own resolved log path. Exported so a host can drive the tool without booting
 * a profile.
 * @param settings - Resolved settings from {@link resolveConfig}.
 * @returns A registry-ready tool definition.
 */
export function createSecretScrubReportTool(settings = {}) {
  const path = resolveIncidentLog(settings)

  return defineTool({
    name: SECRET_SCRUB_REPORT_TOOL_NAME,
    description:
      'Report what this session redacted: the most recent secret-scrub incidents and a count ' +
      'by pattern. Reach for it when a tool argument or result came back containing a ' +
      '$SECRET_<PATTERN>_<8hex> placeholder and you need to know what kind of secret it stood ' +
      'for and how often it appeared. The report holds placeholders and pattern names only — ' +
      'the redacted bytes are not stored anywhere and cannot be recovered by this tool or any ' +
      'other. A placeholder is stable within one session, so the same placeholder in two places ' +
      'is the same secret, and says nothing about any other session.',
    parameters: {
      n: {
        type: 'integer',
        description:
          `How many of the most recent incidents to return. Defaults to ${DEFAULT_REPORT_COUNT}` +
          ` and is capped at ${MAX_REPORT_COUNT}; a larger request is clamped, not refused.`,
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          incidents: {
            type: 'array',
            required: true,
            description:
              'The most recent incidents, oldest first. Each is one distinct secret redacted ' +
              'from one tool call, and carries no trace of the secret itself.',
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                ts: {
                  type: 'string',
                  required: true,
                  description: 'ISO 8601 timestamp of the redaction.',
                },
                session: {
                  type: 'string',
                  required: true,
                  description: 'The scrub session the placeholder is stable within.',
                },
                tool: {
                  type: 'string',
                  required: true,
                  description: 'The tool whose arguments or result held the secret.',
                },
                pattern: {
                  type: 'string',
                  required: true,
                  description: 'The pattern name, matching the middle of the placeholder.',
                },
                placeholder: {
                  type: 'string',
                  required: true,
                  description: 'The `$SECRET_<PATTERN>_<8hex>` text that replaced the secret.',
                },
              },
            },
          },
          counts: {
            type: 'array',
            required: true,
            description:
              'Incident counts by pattern across the returned window, most frequent first.',
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                pattern: { type: 'string', required: true, description: 'The pattern name.' },
                count: {
                  type: 'integer',
                  required: true,
                  description: 'How many of the returned incidents matched it.',
                },
              },
            },
          },
          total: {
            type: 'integer',
            required: true,
            description: 'How many incidents are in `incidents`, after the cap was applied.',
          },
          log: {
            type: 'string',
            required: true,
            description: 'The incident log path that was read.',
          },
          plugin: {
            type: 'string',
            required: true,
            const: PLUGIN_NAME,
            description: 'The plugin that registered the tool that answered.',
          },
        },
      },
      render: (_args, value) => [
        {
          type: 'text',
          text:
            value.total === 0
              ? 'secret-scrub: no incidents recorded'
              : `secret-scrub: ${value.total} incident(s) — ` +
                value.counts.map((row) => `${row.pattern}×${row.count}`).join(', '),
        },
      ],
    },
    execute(args) {
      const incidents = readIncidents(path, clampReportCount(args.n))
      return Promise.resolve({
        incidents,
        counts: countByPattern(incidents),
        total: incidents.length,
        log: path,
        plugin: PLUGIN_NAME,
      })
    },
  })
}

/**
 * Register the plugin's single tool for the lifetime of this plugin's fiber.
 * @param ctx - The injected Cordis context, with `tools` resolved.
 * @param config - The `config` block of this plugin's row in the composed patch.
 */
export function apply(ctx, config = {}) {
  ctx.tools.register(createSecretScrubReportTool(resolveConfig(config)))
}
