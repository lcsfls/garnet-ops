# ADR 0013: AI triage with a local OpenAI-compatible model

- Status: accepted (2026-10-21)
- Date: 2026-10-21
- Decided by: maintainer (one shared thread per finding, each message with its author)
- Implements: ROADMAP Phase 2 "AI triage" (endpoint configuration with connection test,
  triage chat per finding streamed over SSE, context builder, prompt-injection defences,
  structured triage result). Fix pull requests are not part of it; see "The seam for fix
  pull requests".
- Builds on: ADR 0003 (stack), ADR 0004 (vault: the API seals, only the worker opens),
  ADR 0008 (gates: AI never changes a result), ADR 0010 (outbound address rules)

## Context

Every finding can be discussed with the customer's own model (vLLM, Ollama, LiteLLM, LM
Studio: anything that speaks the OpenAI API). That is useful and dangerous at once:

- The model reads text that attackers can write: advisory text, package names, file paths,
  repository and branch names. It may be talked into saying anything.
- What we send is customer data. AGENTS.md: "no customer code, finding or log leaves the
  customer's network unless the customer explicitly configures it."
- The endpoint address is typed by an admin, so it is a server-side request that can be
  aimed at the network around GarnetOps.
- The answer is untrusted output (AGENTS.md rule 1): never executed, never merged, never
  rendered as HTML, never able to change a gate result or a setting.

## Decision

### 1. Who talks to the model: the worker, and only the worker

The API key is sealed in the vault (purpose `ai-api-key`, ADR 0004); only the worker can
open it, so only the worker calls the model. The API never needs the secret:

1. The API stores the user's question as a message and an empty assistant message with
   status `pending`, and queues a job (`ai.generate`, no retries) for that message.
2. The worker claims the message (`pending` to `streaming`), builds the prompt, calls the
   model with `stream: true` and appends what arrives to the message in steps of about
   120 ms. Every step is one SQL statement that appends the text **and** sends a PostgreSQL
   `NOTIFY` on the thread's channel (`ai_<thread id>`), so the stored text never falls behind
   what was announced.
3. The API's `GET /api/v1/ai/threads/:id/stream` (session cookie, organisation scoped)
   relays the notices to the browser as server-sent events with a heartbeat. It starts with
   a `snapshot` of the stored messages, which is also how a reconnect resumes: the client
   continues from the stored text. Offsets are UTF-8 byte offsets; a notice that is already
   contained in the snapshot is ignored, a gap triggers a new snapshot. The stream ends with
   `done` when nothing is pending any more, so the browser does not reconnect needlessly.
   One shared `LISTEN` connection serves all streams of a process and re-listens (and
   re-snapshots) after a connection loss.
4. Stop sets the message to `stopped`; the worker notices at its next write (or within 1.5 s
   when the model is quiet) and closes the connection to the model.

"Load models" and "Test connection" follow the same path: the API stores a probe row (the
typed key is sealed for it and deleted by the worker afterwards), the worker makes the call
and writes the result; the browser polls the row. A probe returns model names, latency and
the length of the reply, never the reply.

No new dependency: `pg` (LISTEN/NOTIFY), pg-boss and `node:http(s)` are already there.

### 2. Where the model may live

| Model server address | Allowed |
| --- | --- |
| Same host or same Docker network as the worker: the address lies inside a subnet of one of the worker's own non-loopback network interfaces (a Compose service such as `http://ollama:11434/v1` on the worker's network, or the Docker host through the bridge gateway) | http or https |
| VPN overlay 100.64.0.0/10 (NetBird, Tailscale; also in IPv4-mapped notation) | http or https |
| Other private addresses (RFC 1918 LAN: 10/8, 172.16/12, 192.168/16; IPv6 unique local fc00::/7) | **https only** (error `insecure-private`) |
| Public (everything else) | https **only**, and only after an owner or admin confirmed this host: finding data leaves the network |
| Loopback, link-local (169.254.0.0/16, fe80::/10, cloud metadata), unspecified, multicast, reserved, `localhost` | always refused |

Why plain http is limited to these two places: the request carries the vulnerability list
of the customer's repositories and servers, which is a map for an attacker. On a LAN that
is cleartext for anyone who can sniff or ARP-spoof on the segment (a compromised
workstation, a rogue device, a switch with port mirroring). On the same host or Docker
network the traffic never leaves the machine's own virtual switch, and a WireGuard-based
overlay (NetBird, Tailscale) encrypts every packet itself, so neither exposes it. Everything
else on a network needs TLS; a reverse proxy in front of the model server does that
(docs/ai.md shows one). The first version of this ADR allowed http on every private
address; it was never released, and this rule replaces it.

Loopback is refused because inside a GarnetOps container it is the container itself, never
the model; a model on the Docker host is reached through the host's private address.
Mixed answers count as the strictest address (plain http needs **every** answer to be on the
same host or in the overlay). IPv6 is parsed to bytes, so mapped, NAT64,
6to4 and expanded notations are judged by the IPv4 address inside.

The rule runs twice. The API judges the typed address when it is saved or probed (it
resolves the name, connects to nothing) to give an answer at once; in the Compose stack the
API has no route to the outside and may not resolve the name, then the endpoint stays
"unknown" until the worker has seen it. The API also cannot know which networks the worker
is on, so for plain http to a private address that is not in the overlay range it does not
refuse but stores "unknown" and lets the worker decide. The **worker repeats the rule on
every connection and is authoritative**: it reads the subnets of its own non-loopback
network interfaces from the operating system (never from configuration or the environment,
so a setting cannot widen them), resolves the name, checks every answer, and
connects to the address it checked (the name travels only as SNI and `Host`), so DNS cannot
change its answer in between. No redirects, TLS verification always on (no switch to turn it
off), bounded time for every phase, bounded size for every answer. A self-signed model
certificate is trusted by adding its CA to the worker container (`NODE_EXTRA_CA_CERTS`),
not by switching verification off. Certificate pinning is not part of this ADR.

The confirmation is stored with the host it was given for (`external_ack_host`), who gave it
and when; a different host asks again. The settings show a persistent warning badge, and
the panel in every finding shows it too, as long as the endpoint is outside the network.

### 3. Settings

Settings, AI is for owners and admins; saving, removing and probing need a sign-in from the
last ten minutes (step-up), and everything is in the audit log (`ai.settings_changed`,
`ai.settings_deleted`, `ai.external_acknowledged`, `ai.endpoint_tested`). The key is sealed,
never returned and never logged. A configuration is **off** until an admin switches it on;
removing it deletes the key. Limits: longest answer (64 to 8192 tokens, default 1024),
temperature (default 0.2), time limit (10 to 600 s, default 120) and answers at the same time
for the organisation (1 to 8, default 2).

### 4. One thread per finding, shared in the organisation

Everybody who can see a finding sees its conversation; every message records who asked
(shown by name, never by e-mail). Members and above can ask; viewers can read. A thread is
per finding, not per person, because the point is a team's shared triage and because the
first answer is expensive. Cost of this choice: a question one person asked is visible to
the rest of the team. The first assistant turn is the structured triage; follow-ups are
free text. Deleting a finding deletes its thread.

### 5. What the model receives (the context builder)

`packages/core/src/ai.ts`, pure and tested. Facts, all read from our own tables: the
vulnerability id, aliases, severity, CVSS score and vector, EPSS, known exploited, dates and
the advisory text; the package name, installed version, ecosystem, fixed versions, fix
state and the paths inside the repository (from the SBOM); the repository name and branch;
and **counts** of other repositories and servers with the same vulnerability (counts, not
names).

Never: tokens, keys, passwords, deploy keys, clone URLs, user names or e-mail addresses,
source code (GarnetOps keeps no clones; code excerpts are a separate, later decision, and
the settings column for it, `context_policy`, stays `metadata`). Secrets are not read in the
first place; as defence in depth every piece of scanned text is cut to a size, stripped of
control and invisible characters (zero-width, bidirectional controls, the Unicode tag
block) and run through a redaction of common credential shapes (private keys, AWS, GitHub,
GitLab, Slack and Google keys, JWTs, bearer tokens, `user:password@` in URLs,
`password=…`). It is a net, not a promise to find every secret.

The text of the system prompt is fixed in code. Everything that comes from scanned data is
one JSON document between markers with a random boundary
(`<<<UNTRUSTED-DATA <24 hex>` … `UNTRUSTED-DATA <24 hex>>>>`), including package, path,
repository and branch names; the fixed rules say that the block is data and that
instructions inside it are never followed. The boundary exists only after the content was
written, so content cannot contain it. The context is limited to 12,000 characters, a
follow-up question to 2,000, a request to 32,000 (oldest turns drop first, never the
context), 8 earlier turns at most. The exact first message is stored with the answer and
shown to people as "What the model saw".

### 6. Treating the answer

- The triage is requested as JSON and parsed leniently (a fenced block or words around it
  are fine) into a zod shape: `exploitability` (likely, unlikely, unknown), `reachable`
  (yes, no, unknown), `confidence` (low, medium, high), `summary`, `recommendation`,
  optional `upgradeTo` (a version-shaped string, nothing else) and `references`. Odd enum
  values become "unknown"; fields that are not part of the shape (a `severity`, a `state`,
  a `gate`, a `command`) are dropped; texts are cut and cleaned. **References survive only if
  they are in our own vulnerability data**; everything else is dropped. Without a usable
  summary the answer is shown as text with a notice.
- The stream is untrusted too. It is parsed defensively: broken events are skipped, a
  stream that is all noise is an error, an event beyond 256 KB is dropped, the response is
  cut at 4 MB and the answer at 32,000 characters (then flagged `too-large`), a stall ends
  with `timeout`, reasoning blocks (`<think>…</think>`) are hidden, NUL, control and
  invisible characters are removed before anything is stored. An error body of the model
  server is never stored or shown, only a short code.
- It is **never executed, never merged and never able to change** a severity, a finding's
  state, a gate result or a setting. The worker's only writes are the message it was asked
  to produce, the probe result, and the observed endpoint scope. A test with an injection in
  the advisory text and a model that obeys it asserts that finding, gate run, rules,
  settings and notes are byte-for-byte unchanged.
- Markdown is rendered by a small parser of our own (`apps/web/src/lib/markdown.ts`) into
  a tree of a few node types, then to React elements. There is no raw HTML path; text is
  escaped by React. Links exist only for `http(s)` addresses without credentials, open with
  `rel="noopener noreferrer nofollow"` in a new tab and name their host; any other link is
  shown as text with its address. Images are not rendered. Input, blocks and nesting are
  capped and the parser is linear. The Content Security Policy is unchanged (no inline
  script, no inline style; the stream is same-origin).
- A suggestion is always labelled "AI suggestion". A human can **take it over as a note** on
  the finding (author is that person, audit `ai.note_accepted`); that is the only way it
  persists beyond the conversation.

### 7. Budgets and limits

Per person 12 requests a minute and per organisation 40 (the `rate_limit` table, so they
survive restarts); answers at the same time per organisation as configured (default 2),
one answer at a time per thread; 6 open event streams per person; the sizes above; the
longest answer in tokens as configured. A generation whose worker disappeared is marked
failed (`interrupted`) after 15 minutes. Every request is audited as `ai.request` with the
finding id, the model and the kind (triage, follow-up, regenerate), **never the prompt
or the answer**.

### 8. The seam for fix pull requests

The Fix proposals page and "Create PR" are a later task. It can rely on: threads and
messages per finding (`chat_thread`, `chat_message`), the validated triage result in
`chat_message.structured` for a message of kind `triage`, and the audit trail. It must take
fixed versions from the finding (`fixed_in`, from the scanner), **not** from the model's
`upgradeTo`, which is a hint a human reads. A write credential for the repository stays a
separate, explicit opt-in per repository and its use a separate audit action.

## Threat model

| Threat | Mitigation |
| --- | --- |
| **Prompt injection** from advisory text, package names, paths, repository or branch names, or an earlier answer | Fixed system prompt; all scanned text in one JSON block with a random boundary and a rule that it is data; invisible characters removed; the model has no tools and no way to act; output is validated and filtered; a human decides everything. Injection can still make the model give bad advice; hence the label, the "what the model saw" view and "unknown" as the honest answer |
| **Data exfiltration to a remote endpoint** | Off by default; plain http only on the same host or Docker network as the worker and inside a VPN overlay, other private addresses over https, public ones only over https after an explicit, audited, per-host confirmation; persistent warning; the worker re-checks every connection; only the data listed in section 5 is sent; nothing in an answer is fetched automatically (no images, no previews), and the references of a triage are limited to our own data. A link in a free-text answer is shown with its host and needs a click; a reader can be misled by it, which is why the answers carry a label |
| **SSRF through the base URL** (a stolen admin session aims GarnetOps at an internal service or the metadata endpoint) | Admin only, step-up and audit; loopback, link-local, metadata, unspecified and multicast always refused in every IP notation; resolve, check and connect to the checked address; no redirects; no response body is stored; probe results contain codes, names and numbers only; the probe is rate limited. A reachable private service that answers like a model server is still reachable; that is the nature of the feature |
| **Eavesdropping or tampering on the way to the model** (a compromised device on the LAN sniffs or ARP-spoofs the cleartext request and sees the vulnerability list, or injects a forged answer) | Plain http is refused for every private address except the worker's own networks (same host, same Docker network: traffic does not cross a shared segment) and the 100.64.0.0/10 overlay (WireGuard encrypts it); the LAN needs https with a verified certificate. The worker decides on every connection from its own interfaces, so an admin cannot widen the rule; a wrong guess of an admin about the network ends in an error code, not in cleartext. Residual risk: a Docker network or a VPN peer that is itself compromised; a /8 or /12 interface subnet of the worker (some clouds) makes that whole range count as "its own network" |
| **Model output used as HTML or a command** | Never: text nodes only, a link allow-list, no images, no raw HTML path; `upgradeTo` is a version-shaped string shown as text; nothing from the model is passed to a shell, a file or a Git operation |
| **Secrets in prompts** | Secrets are not read; scanned text is redacted; the API key is only in the worker, only while a request is made, and never in logs, errors, notices or audit data |
| **Resource exhaustion** (cost, memory, a model that never stops) | Rate limits, concurrency limits, input and output budgets, stream and event caps, wall-clock and idle timeouts, stale-generation sweep, bounded notices (at most 1,000 bytes of text each) |
| **Stored XSS through streamed Markdown** | The renderer cannot produce HTML; CSP unchanged; the event stream carries JSON and is displayed as text; tested with script tags, `javascript:` and `data:` links, entities and attribute injection |
| **Cross-tenant leakage** | Every route scopes by the actor's organisation; notices travel on a channel named after the thread and a stream is opened only after the thread was checked; a test writes to another organisation's channel and sees nothing |
| **Compromised model server** | It receives only the data of section 5, can answer with anything (see above), and sees the API key it was given, which is sent only over the checked connection |

## Consequences

- Migration 0012 (additive): `ai_settings` gains `enabled`, limits, `endpoint_scope` and the
  confirmation columns; `chat_message` gains `seq`, `kind`, `structured` and `error`
  (status `pending` is new in the application; the column is plain text); `chat_thread`
  gains a unique index per finding; new tables `ai_probe` and `finding_note`. The tables
  `ai_settings`, `chat_thread` and `chat_message` existed since the first migration and were
  unused.
- New queues `ai.generate` and `ai.probe`; new audit actions (`ai.*`); new endpoints under
  `/api/v1/ai/…` and `GET /api/v1/findings/:id/notes`.
- The reverse proxy must not buffer the event stream: the API sends
  `Cache-Control: no-store, no-transform`, and the Caddyfile flushes it immediately.
- Follow-ups, not decided here: code excerpts with secret removal (needs clones or a read
  path), certificate pinning for the model server, token counting when a server reports no
  usage, per-user conversations if teams ask for privacy, and an expected-fingerprint option
  for the model host.
