# ADR 0021: Globe view and live attack feed

- Status: accepted (2026-10-22)
- Date: 2026-10-22
- Decided by: maintainer (a globe on the Attacks page, arcs to the organisation's home location, and a live feed of the
  newest attack alerts from Wazuh)
- Builds on: ADR 0015 (read-only Wazuh integration: fixed query templates, pinned certificates, hostile alert text),
  ADR 0016 (attack overview: local GeoIP, optional OSINT, retention of source addresses), ADR 0019 (the shared LISTEN
  connection and the event stream pattern), AGENTS.md rules 1, 3, 5, 6 and 7

## Context

The Attacks page (ADR 0016) shows where failed logins and attacks come from as a flat map and tables, from numbers that
the Wazuh sync aggregates every 15 minutes. Two things were missing: a picture that shows *where the attacks are
heading* (the mockup's globe with arcs to "your network"), and a sense of what is happening *now*, between two syncs.

Three facts shape the design:

- **The feed is a window, not a log.** GarnetOps is not a SIEM (AGENTS.md). The live feed shows the newest few alerts so
  that an admin sees an attack as it starts; the numbers of the page stay the 15-minute aggregates, and the page keeps
  their "updated" time.
- **Every alert is written by someone else.** Rule descriptions and agent names are attacker-influenced text (ADR 0015
  section 7). Source addresses are personal data (ADR 0016 section 5). Reading single alerts instead of aggregates
  makes both more visible, so the feed reads as little as the page shows and keeps it as briefly as the other
  addresses.
- **We poll; nobody calls us.** The integration is outbound and read-only. The feed adds no inbound endpoint, no
  webhook and no write to Wazuh.

Licence (AGENTS.md rule 3): `d3-geo` 3.1.1 (ISC) draws the globe. Its only dependency is `d3-array` 3.2.4 (ISC), which
depends on `internmap` 2.0.3 (ISC). `@types/d3-geo` 3.1.0 (MIT) is a development dependency, and its `@types/geojson` is
types only. All are listed in `docs/COMPONENTS.md`. The country shapes are the Natural Earth 1:110m data already
vendored for the flat map (public domain, via world-atlas, ISC). Nothing is loaded from a server at run time.

## Decision

### 1. The globe

`apps/web/src/components/attack-globe.tsx` draws an orthographic SVG globe with `d3-geo` (sphere, graticule, one path per
land area) and is loaded as a separate chunk only when the globe is shown. The flat map stays and is chosen with a
segmented control **Globe | Map**; the choice is kept in `localStorage` of this browser only (every access in
`try`/`catch`; without storage the globe is shown and the choice lasts for the page). The globe is the default at every
width; below the wide step it stacks above the lists and keeps an aspect ratio, from wide it sits left with the events
and the lists beside it (container queries on the content area, AGENTS.md rule 5), from xwide it is globe, events and
lists three across.

- **Geometry.** `scripts/build-world-map.mjs` now also writes `apps/web/src/assets/world-geo.ts`: the same shapes as a
  TopoJSON subset in longitude and latitude (shared, delta-encoded arcs; 105 KiB, about 25 KiB compressed), including
  Antarctica and the two areas without an ISO code (drawn as neutral land so the globe has no holes), and the centroid
  of each country's **largest part** (France starts in Europe, not in French Guiana). `apps/web/src/lib/world-geo.ts`
  decodes it (the few lines of topojson-client that are needed; no further dependency). The flat map's `world-map.ts`
  is byte-identical to before.
- **Colour.** Countries are filled by alerts on the existing single-hue steel-blue scale (five steps); never a severity
  colour, never burgundy. The home marker is a ring and dot in the neutral foreground colour.
- **Arcs.** One great-circle arc per source country, from its centroid (or, for a country too small for the 110m shapes,
  its capital) to the home point. **Stroke width is one of three steps** by count on the square-root scale of the map
  (`arcStep` in `packages/core/src/attacks.ts`; 1.25, 2 and 3 px) so no precision is invented. An arc is **vermilion
  when the cached OSINT abuse score of any address of that country is above 80**, only while OSINT is on and a score
  exists, and orange otherwise (the fixed critical and high chart colours). The legend lists "High abuse score" only
  when OSINT is on, "Observed" and "Your network".
- **Motion** (AGENTS.md rule 6). Arcs draw in once on load, each over 0.8 s with a start delay of at most 0.35 s, so a load
  finishes within 1.2 s. A live arc (section 5) draws in over 1.1 s, stays 3.5 s and fades over 2.5 s. Nothing pulses or
  bounces. The globe **turns slowly** (4 degrees a second, drawn at 30 frames a second) only while it has not been
  touched, does not have focus and the system does not ask for less motion; under `prefers-reduced-motion` it does not
  turn, there is no rotation button, and arcs appear at once. **No frame is requested while the tab is hidden**
  (`document.hidden`, `visibilitychange`), and live arcs are not created for a hidden page. A button "Pause rotation" /
  "Turn slowly" stops and starts the slow turn (WCAG 2.2.2).
- **Interaction.** Dragging (pointer events with capture, one finger horizontally on touch) turns the surface; the
  focusable globe turns with the arrow keys (10 degrees a step) and shows a focus ring. Latitude is limited to 75 degrees.
  `ResizeObserver` sizes the picture to its frame. Frames are drawn by setting attributes of the existing elements, not
  through React, so a turning globe costs no renders. Colours and widths are classes and presentation attributes: the CSP
  has no inline styles.
- **Accessibility.** The SVG is `role="img"` with an `aria-label` that names the busiest countries; the frame is a
  button (focus, keys) described by a visible hint; the lists beside the picture carry the same numbers as tables and stay
  the route for keyboard and screen reader users.
- **Without a home location** the sources are points, there are no arcs, and a hint links admins to the setting.

### 2. Home location

A country (ISO 3166-1 alpha-2, from `packages/core/src/countries.ts`, which also holds each country's capital and is the
only list the API accepts) and optionally a point with **two decimals** (about one kilometre), typed by hand or taken from
the capital. **There are no default coordinates.** With a country only, the globe uses the country's capital; without a
home, nothing is drawn as a line. Stored in `attack_settings` (`home_country`, `home_lat`, `home_lon`, with database checks
for the ranges and for "both or neither"). Everyone in the organisation reads it (it is in `/attacks/overview`); owners and
admins change it under Settings, Attack overview. It is not a credential and nothing leaves the network, so no recent
sign-in is needed; **every change is audited** (`attacks.home_changed`, `attacks.home_removed`). Coordinates are validated
and rounded in `checkHomeLocation` (also used for the form): a number, in range, both or neither; a string, an exponent or a
country that is not in the table is refused.

### 3. The live attack feed

#### 3.1 What is asked

A **new fixed query template** `liveAlerts` in `packages/core/src/wazuh.ts`, on the same `POST <alert index>/_search` path
the allow-list already permits (the allow-list checks method and path; this template is one more question the client can
build, not a new way to build one). Its only inputs are a `Date` that the worker parsed itself and writes in one fixed
format, and a whole rule level between 3 and 15; anything else throws before a request exists (tested with forged
strings, `NaN`, out-of-range and non-integer levels). Nothing an alert said is ever interpolated.

- `size` 50 (never more), a 10 s search timeout, `track_total_hits: false`, sorted by `@timestamp` ascending.
- Filter: `@timestamp >= cursor and < now`, `rule.level >= minLevel` (default 7, configurable 3 to 15), `rule.groups` one of the
  fixed attack and authentication-failure groups of ADR 0015, and `data.srcip` exists (an event without an address cannot be
  placed on the globe and is not an attack source).
- `_source` is **exactly** eight fields: `@timestamp`, `rule.id`, `rule.level`, `rule.description`, `rule.groups`, `agent.id`,
  `agent.name`, `data.srcip`.

Fields **left out on purpose**: `full_log` (raw log lines hold user names, paths and sometimes secrets; never requested,
never stored), `data.srcport` (an ephemeral client port that identifies nothing an admin can act on), `data.dstuser` (the
user name an attacker tried: attacker-controlled, and often a real person's name or e-mail address), the MITRE tactic and
every other `data.*` field. The parser reads only the eight fields, so a log line in an answer is ignored even if a
server sends it (tested with fixtures that contain `full_log`, a port and a user name).

**The lower bound includes the cursor (`>=`, not `>`).** Alerts carry millisecond times; an alert indexed a moment after the
poll that already saw an alert of the same millisecond would be lost with `>`. With `>=` the alerts of the newest
millisecond are read again at the next poll and stored once (unique `connection_id, doc_id`), so nothing is dropped and
nothing is shown twice. If a whole page shares one millisecond the cursor would never move; it then steps one millisecond
and the few alerts of that millisecond that did not fit are lost (`nextCursor`, tested). Alerts that the indexer makes
searchable *later* than newer ones (ingest lag) can still be missed: the feed is a window, and the aggregates are the record.

#### 3.2 When and how often

- The worker (`apps/worker/src/wazuh-live.ts`) looks for due connections every 5 s and polls each at its own interval:
  **30 s by default, 15 to 300 s per connection** (Settings, Attack overview; database check). The interval is the *only*
  load: one request, at most 50 alerts, a response cap of 1 MiB, the usual 20 s request timeout, no retry within a poll.
- A **row lease** (`next_poll_at` set into the future by an atomic update) makes two workers, or two ticks, poll the same
  connection once.
- **Only while healthy:** the connection is switched on, the feed is on, **both certificates are confirmed and unchanged
  (pinned, or the uploaded authority)**, extra privileges of the Wazuh users are acknowledged, and a sync has run (the
  adapter is known). A connection that fails any of these is not contacted; it is looked at again after a minute.
  The password is opened for the seconds of a poll. A certificate other than the pin is detected before the first byte of the
  request, exactly as in a sync: the endpoint is flagged `changed`, audited once, and the feed pauses.
- **Back-off:** after an error the next poll is `interval x 2^failures`, at most ten minutes; the first good answer resets it.
  A rejected password, a 429, a redirect and a timeout are errors like any other and are not retried faster. The error is
  stored as a short code (`wazuh_live_state.last_error`), never as text from Wazuh.
- **No backfill flood:** the first poll of a connection starts five minutes back; whatever the cursor says, a poll never
  reaches back more than 15 minutes (a worker that was away does not replay hours). After a full page the next poll comes
  after 5 s, at most five times in a row, then the normal interval.

#### 3.3 What is stored

`wazuh_attack_event` (migration 0019, additive): the eight fields plus the indexer's document id and the time it was stored.
**The newest 500 per connection** are kept (trimmed in the same transaction as the insert), and everything older than the
organisation's **retention period of the attack overview** (default 90 days) is deleted by the hourly sweep of ADR 0016 —
source addresses are personal data. "Delete stored addresses now" deletes the events too (the cursor stays, so they do not
come back); removing the connection deletes them by cascade; the audit log holds counts only. The description (200
characters) and the agent name (128) are cleaned of control and bidirectional characters and cut; rule groups are limited to
the fixed list. **They are shown as plain text only (React escapes), are never a link, never HTML and are never sent to a
model**: the AI summaries still read only the aggregated numbers (ADR 0013, 0015 section 11, 0016 section 7).

Country, network and the **cached** OSINT score are not stored with the event: the API looks them up when it reads, from the
local GeoIP tables and `attack_osint_result`, so a dataset loaded later applies to old events and switching OSINT off hides
scores at once. The feed **never triggers an OSINT lookup**; a score appears only if the address was one of the busiest
sources that the normal OSINT run (ADR 0016) checked.

#### 3.4 Realtime to browsers

After inserting, the worker runs `NOTIFY` on **`attack_live_<organisation id>`** inside the same transaction (delivered at
commit); the payload is the newest sequence number and nothing else. `GET /api/v1/attacks/live` is a server-sent-event
stream on the shared LISTEN connection of the API (`listen-bus.ts`, ADR 0013/0019):

- **Session auth** like every `/api/v1` route; every member of the organisation reads (the people who read the page); every
  query and the channel name use the **signed-in person's organisation**, so another organisation's events and notices never
  reach the stream (tested, including a notice on the right channel that names another organisation's number).
- `ready` first (newest sequence number, status), then one `event` per new alert with its sequence number as the event id.
  **Resume** with `Last-Event-ID` (or `?after=`): the missed events are replayed in order, or `resync` when more than 50 were
  missed. `status` follows the heartbeat when the status changed; a comment heartbeat every 15 s keeps proxies open.
- **At most four streams per person** in a process (429 beyond that), and a stream ends after ten minutes; the browser
  reconnects with the last id, which checks the session again.
- `GET /api/v1/attacks/events?limit=` (1 to 50, default 50; rate limited) returns the initial list, newest first, with the
  status. If the stream cannot be opened or breaks, the page **polls this route every 30 s** and retries the stream with a
  growing pause, and says so.

#### 3.5 What the page says

"Live — last event 12 s ago" (the age of the newest event, ticking), "Live — no events yet", "Waiting for Wazuh" (no sync or
poll yet, the last poll failed, with the reason, or the worker has not polled for three intervals and a minute),
"Paused: connection blocked" (switched off, a certificate to confirm, privileges to acknowledge, with the reason) and "The
live feed is switched off". These are neutral (never green: a running feed is not proof of anything). The totals of the page
keep their own "Wazuh data from …" time.

The Attacks page lists the latest events as the mockup does (country code, rule description cut with the full text in the
tooltip, source address as plain text, country, "observed", agent, level, age, and the abuse score only when OSINT is on and
a score exists), at most 50. **Each new event draws a live arc** on the globe (not for internal addresses or countries the
data does not cover). The XDR page has a compact "Latest alerts" card from the same route and stream.

### 4. Permissions, audit

| Action | Who | Recent sign-in | Audit action |
| --- | --- | --- | --- |
| Read the latest events, the stream, the home location | every member | no | none |
| Set or remove the home location | owner, admin | no | `attacks.home_changed`, `attacks.home_removed` |
| Switch the feed on or off, change interval or level | owner, admin | no | `attacks.live_feed_changed` |
| Delete stored addresses (now includes the events) | owner, admin | yes | `attacks.data_purged` (counts) |

The feed's settings can only raise or lower the load on the customer's own Wazuh within fixed bounds and cannot widen what is
read, so they need no step-up. Raising the retention period still does (ADR 0016).

## Threat model

| Threat | What an attacker gains | Mitigation |
| --- | --- | --- |
| The live poll loads the Wazuh indexer | Slow or unavailable Wazuh | One request per interval (15 to 300 s, default 30), at most 50 hits and 1 MiB, a 10 s search timeout and a 20 s request timeout, a row lease against double polling, exponential back-off to ten minutes on every error, no polling of a blocked or unhealthy connection; the catch-up after a full page is five quick polls at most; a cap of four polls in parallel |
| Hostile alert text (descriptions, agent names) | Stored XSS, markup or link injection, layout abuse, prompt injection | A strict parser per hit (valid document id, time, IP address and level or the hit is dropped), control and bidirectional characters removed, text cut at 200 and 128 characters, groups from a fixed list; stored and shown as plain text (React escapes), never a link, never rendered as Markdown or HTML, never sent to a model (tested in the browser with a markup description) |
| Query injection into the indexer | Read other indices, change or delete data | A fixed template; the only inputs are a `Date` and an integer level between fixed bounds; anything else throws before a socket exists; the existing method and path allow-list; read-only role (ADR 0015) |
| Personal data (source addresses) kept too long or shown to the wrong people | GDPR exposure, disclosure across tenants | Only eight fields; the log line, the port and the user name are never read; at most 500 events per connection; the attack overview's retention period applies; erasure on demand; organisation scoping on every read, channel per organisation, notices without content; audit log holds counts only |
| A stolen session reads the stream or floods it | Live view of attacks; resource use | Session auth; four streams per person; ten-minute streams that re-check the session; rate limit on the list; heartbeats only |
| A man in the middle of the poll | The indexer password, forged alerts | The same pin-before-first-byte check as every Wazuh request; a changed certificate pauses the feed and is audited once; TLS 1.2 or newer; no redirects |
| A forged or replayed notice | A browser reloads data it may read anyway | The notice carries a number only; the stream re-reads the rows with its own organisation in the query |
| Missed or duplicated alerts | A wrong picture of "now" | The lower bound includes the cursor and the unique document id removes duplicates; a stalled cursor steps one millisecond; the page says it is a window and keeps the aggregates as the record |
| The globe as a distraction or a barrier | Motion sickness, keyboard traps, wrong conclusions from a picture | Short, purposeful motion only; slow turn stopped by reduced motion, a button, touch and focus; frames stop for a hidden tab; keyboard and text alternatives; tables carry the same numbers; locations are approximate and labelled so |
| A wrong or malicious home location | Misleading arcs; disclosure of the premises | Admin-only, validated, rounded to about a kilometre, audited; no default; the point is shown only to the organisation's own members |

## Consequences

- Migration 0019 (additive): `wazuh_live_state`, `wazuh_attack_event`, and `home_country`, `home_lat`, `home_lon` on
  `attack_settings`. New audit actions `attacks.home_changed`, `attacks.home_removed`, `attacks.live_feed_changed`. API:
  `GET /attacks/events`, `GET /attacks/live`, and `home` / `liveFeed` in `/attacks/settings` and `/attacks/overview`
  (additive). The overview's countries gain an optional `topScore`.
- **Upgrade behaviour (AGENTS.md rule 2):** the live feed is on by default for an existing Wazuh connection once the new
  version runs, which adds one small indexer request every 30 s. It can be switched off (or slowed) under Settings, Attack
  overview. It needs the indexer role that ADR 0015 already requires (read access to `wazuh-alerts-*`); no new permission.
- `d3-geo`, `d3-array`, `internmap` (ISC) and `@types/d3-geo` (MIT, development) are added to the web app.
- Not done: a history of events (by design), filtering or acknowledging single events, blocking or reporting addresses
  (GarnetOps only reads), per-event OSINT lookups, geolocation more precise than a country for the arcs, and a check against
  a real Wazuh 5.x indexer (the field names are the ones ADR 0015 assumes). The feed was tested against a local HTTPS server
  that replays synthetic answers, not against a running Wazuh.
