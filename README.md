# dsh-secret-scrub

A **DeepSeek Harness function plugin** that redacts known secret shapes **on the
way in and out of tool execution**, and writes an append-only JSONL incident
line for each one — **without the preimage**.

A tool argument holding a token is redacted *before the tool runs*, and a tool
result holding one is redacted *before the model sees it*. Each distinct secret
becomes a stable placeholder:

```
$SECRET_GITHUB_PAT_3f9a1c04
```

The same bytes produce the same placeholder for the rest of the session, so the
model can still reason about "the token in the argument came back in the
result" — and the bytes themselves are gone, from the transcript and from the
log alike.

## What it is not

> **This is pattern redaction. It is not a secret manager.**

- **Not a secret manager or a vault.** It stores nothing, issues nothing,
  rotates nothing, and verifies nothing. If a secret was leaked into a prompt,
  redacting it here does not un-leak it: **rotate it.**
- **Not a preimage log.** The incident line names the pattern and the
  placeholder. The matched bytes are hashed once, in memory, and dropped. There
  is no reverse map on disk and no API that returns one — not even to the tool
  that reports incidents.
- **Not a detector model.** There is no classifier, no entropy heuristic, and
  no scoring. It matches the shapes in the table below, and only those. A
  credential with a shape not in the table passes straight through.
- **Not a live scanning API.** Nothing is validated against GitHub secret
  scanning, AWS STS, or any other issuer. A match is redacted whether or not it
  was ever a live credential, and a redaction is not evidence of a leak.
- **Not DLP.** It does not watch files, egress, or a mail flow. It sits on one
  seam — tool arguments and tool results — and nothing else passes through it.

Redaction is **damage limitation, not a control**. The control is not putting
credentials where a model can read them.

## Where it sits, and the seam it does not invent

`dsh-telemetry-redactor` scrubs the **export** copy: the transcript you ship
somewhere else. This plugin scrubs the **live** copy, before the model or the
tool sees it. They are complementary and neither replaces the other.

The pinned release candidate `0.1.1-rc.2` exposes **no tool-execute middleware
seam**, so this package does not pretend to have one. It registers exactly one
model-facing tool, `secret_scrub_report`, and exports `wrapExecute` for a host
to apply where it owns the call. Nothing is monkey-patched and no private
API is reached into.

## Install

```sh
dsh plugin --profile default add github:jwilson411/dsh-secret-scrub
```

`dsh plugin` forwards to pnpm inside `$DSH_HOME/profiles/default`, then
reconciles the profile: because this package's manifest declares
`dsh.bundle.patch`, it is appended to the profile manifest's ordered
`dsh.profile.bundles` list and its `cordis.patch.yml` becomes a layer. Remove it
the same way, with `remove` in place of `add`.

## Pinned DSH release candidate

This package is written and tested against the pinned release candidate
**`0.1.1-rc.2`** — `@deepseek-ai/dsh-tools@0.1.1-rc.2` is pinned exactly in
`devDependencies` so tests run against one known API, and the peer range is
`^0.1.1-rc.2`, matching how the harness's own tool packages declare it.

## What it registers

| | |
|---|---|
| Cordis plugin id | `secret-scrub` (the row id in `cordis.patch.yml`) |
| Injects | `tools` — a hard dependency; the plugin waits rather than degrading |
| Tool | `secret_scrub_report` |
| Arguments | `n` (integer, optional; default 20, capped at 200) |

## Patterns

Each pattern has a **stable name** that appears verbatim inside every
placeholder and every incident line, a **version** bumped whenever its regex
changes shape, and the **date** it was added. Names are public API — renaming
one would orphan every stored incident. Regexes are not.

| name | version | since | matches |
|---|---|---|---|
| `GITHUB_PAT` | 1 | 2026-08-31 | GitHub classic personal access token, `ghp_` + 36 |
| `GITHUB_FINE_GRAINED_PAT` | 1 | 2026-08-31 | GitHub fine-grained personal access token, `github_pat_` + 40 or more |
| `AWS_ACCESS_KEY_ID` | 1 | 2026-08-31 | AWS long-lived access key id, `AKIA` + 16 |
| `SLACK_BOT_TOKEN` | 1 | 2026-08-31 | Slack bot user OAuth token, `xoxb-` + two numeric segments + a secret segment |
| `PEM_PRIVATE_KEY` | 1 | 2026-08-31 | A PEM private key block, or its header alone |
| `SK_LIVE_TOKEN` | 1 | 2026-08-31 | Generic `sk-` prefixed live API token |

The regexes, verbatim from `src/scrub.js`:

```js
GITHUB_PAT               /\bghp_[A-Za-z0-9]{36}\b/g
GITHUB_FINE_GRAINED_PAT  /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g
AWS_ACCESS_KEY_ID        /\bAKIA[0-9A-Z]{16}\b/g
SLACK_BOT_TOKEN          /\bxoxb-[0-9]{8,}-[0-9]{8,}-[A-Za-z0-9]{16,}\b/g
PEM_PRIVATE_KEY          /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g
SK_LIVE_TOKEN            /\bsk-[A-Za-z0-9_-]{20,}\b/g
```

`PEM_PRIVATE_KEY` has two branches, longest first: a complete armoured block
collapses to **one** placeholder, so the key material inside goes with the
header rather than being left behind under a redacted header. The second branch
catches a header whose body was truncated before it arrived.

## Placeholders

```
$SECRET_<PATTERN>_<8hex>
```

`<PATTERN>` is the name from the table. `<8hex>` is
`sha256(salt || 0x00 || secret)` truncated to eight hex characters, where the
salt is generated per scrub session.

- **Same bytes, same session → same placeholder.** That is what makes the
  redacted text still reasonable about.
- **Same bytes, different session → different placeholder.** The salt is fresh
  per session, so one session's log cannot be joined against another's, and a
  placeholder is not a durable identifier for a secret.
- **The digest is not a commitment.** It is short on purpose, to keep redacted
  text readable. Do not build anything on top of it that assumes collision
  resistance, and note that an *unsalted* short digest of a known-shape secret
  would be brute-forceable by anyone holding a candidate list — which is why
  it is salted.

## The library API

The tool is a side channel. The functions are the product:

```js
import { createScrubState, wrapExecute, scrub } from 'dsh-secret-scrub'

// One state per session. It holds the salt and the placeholder memo, and no
// preimages beyond the life of the process.
const state = createScrubState({ session: sessionId })

// Wrap a tool's execute: arguments in, result out, incidents appended.
const execute = wrapExecute(tool.execute, state, {
  tool: tool.name,
  incidentLog: '/var/log/dsh/secret-scrub.jsonl',
})

// Or scrub one value directly.
const { value, findings } = scrub(payload, state)
// findings: [{ pattern: 'AWS_ACCESS_KEY_ID', placeholder: '$SECRET_…', count: 2 }]
```

| export | |
|---|---|
| `createScrubState({ session, salt })` | opens a session; thread it through every call |
| `scrub(value, state)` | recursive walk; returns `{ value, findings }` |
| `wrapExecute(execute, state, meta)` | scrubs arguments in, result out, and appends incidents |
| `scrubToolArgs(args, state, meta)` | one direction, returning `{ args, incidents }` |
| `scrubToolResult(result, state, meta)` | one direction, returning `{ result, incidents }` |
| `appendIncidents(path, incidents)` | append-only JSONL write |
| `readIncidents(path, limit)` | the tail of the log, sanitized |
| `countByPattern(incidents)` | `{ pattern, count }` rows |
| `PATTERNS` | the table above, as data |

`scrub` walks strings, arrays, and plain objects, **including object keys** — a
payload keyed by a token leaks as surely as one that holds it. Arrays and
objects are rebuilt rather than mutated, cycles are handled, and anything that
is not a string, array, or plain object (a `Date`, a `Map`, a class instance) is
passed through untouched rather than flattened.

## Incidents

Append-only JSONL, one line per distinct secret per direction per call:

```json
{"ts":"2026-08-31T12:00:00.000Z","session":"s-1","tool":"read_file","pattern":"AWS_ACCESS_KEY_ID","placeholder":"$SECRET_AWS_ACCESS_KEY_ID_1a2b3c4d"}
```

Five fields, and **only** these five: `ts`, `session`, `tool`, `pattern`,
`placeholder`. No preimage, no prefix, no length, no character count — a
redaction log that leaks a little of every secret it saw is worse than no log.
The file is created `0600`.

The reader is defensive in the same direction: `readIncidents` reduces every
line to exactly those five fields and drops any line whose `placeholder` is not
placeholder-shaped, so a log appended to by something else cannot smuggle a
preimage back out through the report tool.

## Config

| key | type | default | |
|---|---|---|---|
| `incidentLog` | string | `.dsh-secret-scrub.jsonl` | path of the append-only JSONL log, relative to the process working directory |

Resolution order is **patch config, then environment, then default**: a patch
row is the deployment's stated intent, so it is not silently overridden by an
ambient variable. The environment fallback is `DSH_SECRET_SCRUB_LOG`, used only
when the patch row omits the key entirely.

```yaml
- id: secret-scrub
  config:
    incidentLog: /var/log/dsh/secret-scrub.jsonl
```

## The report tool

`secret_scrub_report` answers one question: *what did this session redact?*

```js
{ n: 20 } // optional; default 20, hard cap 200 — a larger ask is clamped, not refused
```

It returns `{ incidents, counts, total, log, plugin }`: the most recent
incidents oldest-first, counts by pattern across that window, and the log path
that was read. Placeholders and pattern names only. **There is no tool, flag, or
export that returns a preimage**, because none is kept.

## Layout

```
package.json          manifest + `dsh.bundle.patch` — what makes this a bundle
cordis.patch.yml      the bundle's patch layer: one insert, one plugin row
src/scrub.js          the library: patterns, placeholders, the walk, the log
src/index.js          the plugin: `name`, `inject`, `apply(ctx, config)`, the tool
test/                 offline tests: the walk, the wrapper, the log, a hygiene scan
package-lock.json     the pinned dependency tree `npm ci` installs in CI
```

## Tests

```sh
npm install
npm test
```

Fully offline. No network, no secret-scanning API, no profile boot: `apply` is
handed a stub context that records registrations, the tool is driven through the
same `execute` the registry calls with results validated against the real
`@deepseek-ai/dsh-tools`, and every incident log is written into a fresh
directory under the OS temp directory and removed afterwards.

### The fixtures are fake, and assembled at runtime

Every fake secret is **built from fragments inside the test**, so no committed
file ever holds a contiguous token of any shape — GitHub push protection has
nothing to reject, and neither does any other scanner:

| pattern | fragments |
|---|---|
| `GITHUB_PAT` | `ghp_` + `fake` + 32 × `x` |
| `GITHUB_FINE_GRAINED_PAT` | `github` + `_pat_` + `fake` + 18 × `0` + `_` + 59 × `y` |
| `AWS_ACCESS_KEY_ID` | `AKIA` + `FAKESECRET` + `111111` |
| `SLACK_BOT_TOKEN` | `xoxb` + `-` + `1111111111` + `-` + `2222222222` + `-` + `fake` + 20 × `z` |
| `PEM_PRIVATE_KEY` | the header words joined with spaces, a `TEST KEY` body, and the footer words |
| `SK_LIVE_TOKEN` | `sk-` + `live` + `-` + `fake` + 24 × `K` |

None of these were ever credentials. They are the right *shape* and nothing
else — which is the whole point of a pattern redactor, and its whole limit.

`test/hygiene.test.js` asserts that rather than claiming it: it runs **the
redactor's own pattern table over its own tree** and fails if any committed file
holds a whole token, scans for machine names, mount paths, and credential
variable names, checks that `src/` contains no socket, fetch, or subprocess
construct and imports nothing but the pinned tools package and the two node
builtins it uses, and checks that CI needs no credentials.

CI (`.github/workflows/ci.yml`) runs `npm ci` and `npm test` on Node 22 and 24
from the committed lockfile, against the public registry only. It holds no
secrets and reaches no network beyond that install.

## Out of scope

- **Secret storage, issuance, or rotation.** Covered above: this is not a
  vault, and a redaction is not a remediation.
- **Recovering a redacted value.** Deliberately impossible here. If you need
  the original, you needed it before it reached the model.
- **Entropy or ML detection.** No scoring, no classifier, no "probably a
  secret". Shapes only, so both the false positives and the false negatives are
  predictable and auditable.
- **Validating a match against its issuer.** No network, ever.
- **Redacting anything but tool arguments and results.** Prompts, system text,
  attachments, and exports are other seams with other owners.
- **Deciding for you.** The wrapper redacts and records. What your deployment
  does about a recorded incident — alert, rotate, revoke — is your deployment's
  business.

## License

MIT — see [LICENSE](LICENSE).
