# ADR 0023: External exposure monitoring with domain verification

> **Status: superseded by ADR 0025 (removed in 0.0.4).** The module was removed when GarnetOps became a pure developer pipeline. The text below is kept as the record of the decision; it describes the last version that has the module, the tag `v0.0.3`.

- Status: superseded by ADR 0025 (removed in 0.0.4). Earlier status: accepted (2026-10-22)
- Date: 2026-10-22
- Decided by: maintainer (watching the organisation's own public assets from the outside, in two stages, the second only for assets
  whose control was proved)
- Builds on: ADR 0002 (what is monitored and how), ADR 0010 and ADR 0013 (address policy: `classifyAddress`, `isForbiddenAddress`),
  ADR 0016 (local GeoIP and ASN tables, opt-in downloads and lookups), ADR 0018 (grades), ADR 0019 (notification catalogue),
  AGENTS.md rules 1, 3, 5, 6 and 7

## Context

A security platform for a sysadmin has an inside view (repositories, servers, Wazuh) and lacks the outside one: what does the internet
see of us? Which certificate is about to expire, which host answers on the database port, which name has no SPF record, which
subdomain points at a name nobody owns any more. These questions are asked about the organisation's **own** domains, host names and
public addresses.

Two things make this different from the rest of the product:

- **GarnetOps becomes the one who connects.** In every other integration GarnetOps talks to something the customer connected on
  purpose (a Proxmox cluster, a console, a Wazuh manager). Here it talks to arbitrary public hosts named by an admin. Used carelessly
  that is a port scanner pointed at third parties, which can be illegal in many countries, can trip other people's intrusion detection
  and can harm infrastructure that belongs to a hosting company or a cloud provider, not to the customer.
- **A domain is not its servers.** Proving that you control `example.com` shows that you control its DNS. The addresses it points
  to may be a CDN, a shared host or a cloud load balancer that nobody agreed to be tested.

The design is therefore built around **proportion**: what any browser or mail server does needs nothing; anything more needs proof
of control and an explicit, audited statement of responsibility, in small steps, with limits enforced in code.

**Not legal advice.** GarnetOps is self-hosted and the operator is responsible for what they check. This ADR describes technical
controls that make misuse harder and mistakes rarer; it is not a statement that any particular use is lawful in any particular
country, and the product says so in the interface and the documentation.

## Decision

### 1. Scope

- **Stage 1, passive** (needs no proof): DNS records, the TLS handshake on port 443, one `GET /` over HTTPS and a look at plain HTTP on
  port 80, GeoIP and ASN from the local tables, and, only if an owner switched it on, Certificate Transparency. This is what a browser, a
  mail server or a monitoring site does for any name on the internet.
- **Stage 2, light active** (needs proof, an acknowledgement per asset, and is off by default): TCP connections to a fixed list of 30
  common ports, reading what a service sends first. No packet that carries a request or a payload is ever sent to a port.
- **Out of scope and not built:** exploitation, brute force, password or credential testing, fuzzing, denial of service, crawling,
  form submission, service fingerprinting by probing, vulnerability matching of banners, raw sockets, SYN scanning and any third-party
  scanner (nmap is under a licence that rule 3 forbids anyway). The code in the worker only connects and reads. A test pins that no
  byte is written to any port except the TLS handshake of the TLS ports.
- **Not CVE matching of banners.** Server banners are shown (a `Server: nginx/1.22.1` header is a fact) with the advice to check whether
  the version is current, but no vulnerability data is matched against them: Debian, Red Hat and others backport fixes without changing
  the version, so such matches are wrong in both directions, and fake precision is a bad answer to a sysadmin (AGENTS.md rule 6).

### 2. Assets

- An asset is a **domain or host name** (RFC 1123: letters, digits and hyphens, labels of 1 to 63 characters, 253 in all, at least two
  labels, a last label that is not a number, none of `localhost`, `local`, `lan`, `internal`, `intranet`, `home`, `corp`, `private`,
  `test`, `invalid`, `example`, `onion`, `arpa`), converted to lower case and to ASCII (internationalised names become `xn--`
  names), or a **single IP address**, canonicalised. No URL, path, port, wildcard or user name.
- **Public only.** An address must pass `classifyAddress(address) === "public"` **and** lie outside the special-purpose ranges that call
  themselves public: `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `192.88.99.0/24`, `2001::/23`,
  `2001:db8::/32`, `3fff::/20`, `64:ff9b:1::/48`, `100::/64`, and the translation and tunnel forms `64:ff9b::/96` and `2002::/16` (`isExternalAddress`). Private, loopback, link-local (including cloud
  metadata), shared (100.64.0.0/10), documentation, benchmarking, multicast and reserved addresses are refused, and so are IPv4-mapped
  IPv6 forms and the NAT64 and 6to4 forms. Tests may open loopback and the documentation ranges
  through a hook that exists only in code and is ignored outside `NODE_ENV=test` (`addressAllowed(address, true)`; the API hook in
  `apps/api/src/lib/exposure-policy.ts`). Private, link-local and metadata addresses stay refused even under the hook.
- At most **200 assets per organisation**, de-duplicated by the normalised value. Adding an asset starts nothing but stage 1.
- **Subdomain discovery is not brute force.** Names are suggested only from (a) the organisation's own DNS answers for an asset
  (CNAME, MX and NS targets under the asset's registrable domain) and (b) Certificate Transparency logs of **verified** domains, when an
  owner switched that on. A suggestion is a row with a name; **nothing connects to it** until an admin adds it as an asset.

### 3. Stage 1 in detail

All outbound connections are made by the worker, with these rules:

- **Resolve, check, connect.** The worker resolves the name itself with the system resolver (`node:dns` `Resolver`), checks **every**
  answer with the address policy and connects to the checked address, with the name only as SNI and `Host` header. If **any** answer
  of a name is not public, nothing is connected to that name at all (a mixed answer is a rebinding trick, or a split-horizon
  configuration, and either way there is nothing safe to do); the finding `dnsNonPublicAddress` records it. At most four addresses of
  a name are looked at.
- **DNS:** A, AAAA, CNAME, MX, NS, CAA (climbing from the name to its registrable domain, RFC 8659), SPF (the TXT records starting with
  `v=spf1`), DMARC (`_dmarc` at the name, and at the registrable domain if the name has none), PTR for address assets. A failed lookup
  (a timeout, SERVFAIL) is recorded as failed, the rules that need it stay silent and the findings of those rules are **left as they
  are** (not resolved): "we could not look" must not read as "fixed" (`unjudgedRules`). DNSSEC: the Node resolver interface does not
  expose the AD flag or DS records, so DNSSEC is **not checked** and the page says so, rather than guessing.
- **TLS:** a handshake (TLS 1.2 or newer, certificate verification recorded but not enforced, so a bad certificate can be inspected)
  gives the protocol, the cipher, the chain verdict of the system store, the name match, the leaf certificate (subject, issuer,
  names, validity, key type and size, SHA-256 fingerprint, self-signed), the chain length. Two further handshakes ask for exactly
  TLS 1.0 and TLS 1.1 (`maxVersion`, `ciphers: "ALL:@SECLEVEL=0"`, because the OpenSSL in Node refuses old protocols at its default
  security level) to learn whether they are still accepted; they send no data. This is what any client does when it falls back. They
  run for the first address that answers.
- **HTTP:** `GET /` over HTTPS and `GET /` over plain HTTP on port 80 (not followed: does it redirect to `https://`?). Follow at most
  **3** redirects, only to the **same registrable domain** or to a host that is a verified asset of the organisation, only on the
  default ports, and re-resolve and re-check every new host. The registrable domain is approximated (the last two labels, or three under
  a two-letter country code with a registry level such as `co.uk`) because this product does not bundle the public suffix list;
  the error is on the cautious side. The response headers are captured from a fixed list (`Server`, `X-Powered-By`, HSTS, CSP,
  `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`), cleaned, cut at 300 characters. The body is read
  up to 64 KiB, counted and dropped; it is never stored. No cookies, no forms, no crawling, `User-Agent: GarnetOps-Exposure-Check/1`.
- **GeoIP and ASN** of each looked-at address from the local DB-IP tables (ADR 0016); without imported data the fields are empty and the
  page says "location unknown".
- Timeouts everywhere (3 s DNS, 8 s handshake, 12 s request), a size cap on everything read, a run budget, one run per asset and
  stage at a time (a unique index on queued or running runs).

### 4. Verification (the proof of control)

Per asset the organisation publishes a **token** in one of two ways:

| Method | What | For |
| --- | --- | --- |
| DNS | a TXT record at `_garnetops-challenge.<domain>` with the value `garnetops-verify=<token>` | domains and host names |
| File | `https://<host>/.well-known/garnetops-verify.txt` containing the token (bare or as `garnetops-verify=<token>`) on a line of its own | domains, host names and addresses |

- **Token:** 256 random bits (43 base64url characters), created per organisation and asset, unique across the installation. **Decision on
  storage:** it is stored **as it is**, in clear, and the Verify dialog shows it whenever an owner or admin opens it, not once. Reason:
  the token is not a secret. It is published in public DNS or on a public web server, by design, so hashing it would add nothing and
  would make the dialog unusable ("where was the value?"). What makes it proof is that it is unguessable and bound to one asset in one
  organisation, so another organisation cannot reuse a token it read off the internet. A new code can be created (step-up); it voids the
  old proof and switches stage 2 off. The API shows the token to owners and admins only.
- **The check** is made by the worker: the TXT answer is matched exactly (the character strings of one record joined, surrounding blanks
  ignored; a longer, shorter or different value is no proof); the file is fetched over HTTPS with the certificate verified (names), or
  over HTTPS with the chain verified and then plain HTTP (addresses, whose certificates rarely name an address and for which the file
  holds only a public token), **never following a redirect**, at most 1 KiB, status 200 only. The address policy applies.
- **Re-checked daily** (the 15-minute tick queues every proof that is a day old) and **again at the start of every stage 2 run**. The
  result is *definitive* only if the method the asset was verified with shows that the proof is gone (the record is absent or different,
  the file is gone, different, redirected or oversized). A *definitive* loss turns `verified` into `lost`, **switches stage 2 off and voids
  the acknowledgement at once**, writes `exposure.verification_lost` to the audit log and tells owners and admins once
  (`exposure.verification_lost`). An *inconclusive* check (a resolver failure, a timeout, a server error, a refused connection) changes
  nothing, but stage 2 needs a proof confirmed within the last **48 hours** and fails closed otherwise. A lost asset is verified again
  when the proof returns, but stage 2 then needs a new acknowledgement.
- **Subdomains:** a verified domain covers its subdomains only if **Include subdomains** is ticked (default off). Coverage is computed
  (`effectiveVerification`), never stored: a subdomain of a domain that loses its proof, loses "include subdomains" or is removed stops
  being covered, and the worker and the API switch stage 2 off for it (`exposure.stage2_stopped`). An address is never covered by a
  domain.
- **Honest limit.** Verification is an accountability control, not a barrier against a malicious operator. Whoever runs a GarnetOps
  installation can change its code (it is AGPL software) and fake any proof locally. The control exists to prevent mistakes, to make
  insider misuse deliberate and traceable, to give a customer something to show an auditor, and to keep an installation that is used as
  intended from ever touching a stranger's hosts by accident (a typo, a leftover name, a re-used address).

### 5. Stage 2 in detail

- **Switching on** (`PUT /api/v1/exposure/:id/stage2`, owners and admins, **step-up**): the asset must be verified (its own proof or a
  covering parent), the request must carry the identifier of the acknowledgement text the person saw (`exposure-stage2-v1`) and
  `confirmed: true`. The dialog shows the warning first: *a verified domain proves control of DNS, not ownership of the infrastructure
  behind it (CDN, shared hosting, cloud); switch on only if you are authorised to test that infrastructure*, what the stage does and never
  does, the 30 ports, the limits, the hint about the customer's own intrusion detection and "not legal advice". The checkbox says: "I am
  authorised to test the infrastructure behind this name." The audit entry `exposure.stage2_enabled` holds who, the asset, the schedule,
  the acknowledgement identifier, how it is verified and the number of ports.
- **Schedule:** daily or weekly. **At most once per 24 hours per asset, whoever asks**: the worker refuses a run if the last one
  started less than 24 hours ago (`lastActiveAt` is written before the first connection, so a run that crashes still uses its day), the
  API refuses a manual run (`409 too-soon`) and the schedule tick does not queue one. A manual run needs a recent sign-in and is audited.
- **The ports** (`EXPOSURE_PORTS` in `packages/core/src/exposure.ts`; an installation cannot add to them): 21, 22, 23, 25, 53, 80, 110,
  143, 443, 445, 465, 587, 993, 995, 1433, 1521, 2375, 2376, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 11211, 27017.
- **Limits, enforced in code:** at most **4** attempts in flight per target and at least **200 ms** between the starts of two attempts
  (`pacedRun`); 3 s to connect; targets (addresses) are scanned one after the other, so the limit holds per asset; at most four
  addresses per name. The proof is checked again before the first connection and the state of the asset (switched on, acknowledged,
  covered by a fresh proof) is read again **before every single attempt**: a switched-off asset or a lost proof stops the run at the next
  port, and a stopped run stores nothing.
- **What is sent:** nothing, except that on a TLS port (443, 465, 993, 995, 2376, 8443) the TLS handshake is made and the certificate is
  read. On the ports where a service speaks first (21 FTP, 22 SSH, 25 and 587 SMTP, 110 POP3, 143 IMAP) the worker waits up to 2 s
  and keeps up to 512 bytes of what the service says, as plain text. On every other port it connects and closes. No function of the
  worker writes to a TCP socket (the socket's `write` is not called anywhere), and the tests assert it with listeners that record every
  byte they receive.
- **Risk table** (the severity says how unusual it is to see the service open to the internet, not that it is vulnerable; GarnetOps sends
  nothing and so cannot tell whether the service is protected):

  | Severity | Ports |
  | --- | --- |
  | critical | 2375 Docker API without TLS |
  | high | 23 Telnet, 445 SMB, 3389 RDP, 5900 VNC, 1433 SQL Server, 1521 Oracle, 3306 MySQL/MariaDB, 5432 PostgreSQL, 6379 Redis, 9200 Elasticsearch, 11211 Memcached, 27017 MongoDB |
  | medium | 21 FTP, 2376 Docker API with TLS |
  | low | 110 POP3, 143 IMAP, 3000, 8000, 8080 (development and alternative web ports) |
  | none (usual) | 22, 25, 53, 80, 443, 465, 587, 993, 995, 8443 |

- **Results:** open ports (address, port, service, banner, TLS details) replace the previous set; findings `portExposed` (one per port)
  and the TLS rules for the other TLS ports. A port that is open now and was not in the previous successful run is **new**
  (`exposure.new_open_port`; the first run is the baseline and says nothing). A `high` or `critical` service is announced once
  (`exposure.risky_service`) and again only if it closed and opened again.

### 6. Certificate Transparency (opt-in, data leaves the network)

- **Off by default per organisation.** Switching it on (`PUT /api/v1/exposure/settings`, owners and admins, **step-up**, an explicit
  `acknowledged: true`) is audited (`exposure.ct_enabled`, `exposure.ct_disabled`). The settings screen shows the **exact request**:
  `https://crt.sh/?q=%25.{domain}&output=json&exclude=expired`, and what it tells the provider (which domains the organisation watches).
- **Which provider, and why this one.** The provider interface is `CtFetch` (`apps/worker/src/exposure-ct.ts`). The one implementation is
  **crt.sh** (Sectigo), a free public search over the CT logs that needs no account or key. Google's CT logs offer no search by name,
  Facebook's API needs an account and a token, and commercial services (Censys, SSLMate's Cert Spotter) need keys and have terms that
  restrict use. **crt.sh publishes no API terms or service level that could be confirmed from the build environment**: it is
  best-effort, rate-limited and sometimes slow. That is why the lookup is opt-in, strongly bounded and said plainly to be unconfirmed
  (`docs/COMPONENTS.md` lists it with "terms not confirmed", like AbuseIPDB). Nothing else depends on it.
- **Limits:** only **verified** domains (their own proof, not a parent's), at most once a day per asset, 100 queries per organisation and
  day, at least 10 s between two queries, HTTPS to the fixed host through the address-checked client of ADR 0016 (`outbound.ts`: every DNS
  answer must be public, TLS 1.2+, no redirects), 30 s timeout, 4 MiB cap. The answer is hostile text: only names that are valid host
  names strictly below the queried domain survive, at most 500, and become **suggestions** (section 2).

### 7. Findings

Plain rules, no scoring, no CVE matching. Each finding has a rule id, a severity from the fixed scale (critical, high, medium, low), a
subject (a port or a header, to tell several apart) and short parameters. They are de-duplicated per asset, rule and subject, opened
when the rule fires, refreshed, and resolved when it stops (except rules the run could not judge, section 3).

| Rule | Severity | Fires when |
| --- | --- | --- |
| `tlsExpired` | high | the certificate has expired |
| `tlsExpiring` | high / medium / low | 7 / 14 / 30 days left |
| `tlsUntrusted`, `tlsNameMismatch` | medium | the chain does not verify against the system store, or the certificate does not list the name |
| `tlsWeakKey` | medium | an RSA key under 2048 bits |
| `tlsLegacyProtocol` | medium | TLS 1.0 or 1.1 is accepted |
| `httpHstsMissing`, `httpHstsWeak` | low | HTTPS page without `Strict-Transport-Security`, or with less than 180 days |
| `httpCspMissing`, `httpNosniffMissing`, `httpFramingMissing`, `httpReferrerPolicyMissing`, `httpPermissionsPolicyMissing` | low | the header is missing (framing: neither `frame-ancestors` nor `X-Frame-Options`) |
| `httpBannerVersion` | low | `Server` or `X-Powered-By` names a version; the banner is shown |
| `httpNoRedirectToHttps` | medium | port 80 answers without sending visitors to HTTPS while 443 is open |
| `httpNoHttps` | medium | port 80 answers and nothing speaks HTTPS |
| `dnsNoSpf`, `dnsNoDmarc` | medium with an MX, otherwise low | no SPF record, no DMARC policy |
| `dnsSpfPermissive`, `dnsSpfMultiple`, `dnsDmarcNone` | medium, medium, low | `+all` or `?all`; several SPF records; `p=none` |
| `dnsNoCaa` | low | no CAA record at the name or up to the registrable domain |
| `dnsDanglingCname` | medium | a CNAME whose target has no address |
| `dnsNonPublicAddress` | low | the name resolves to a non-public address (and nothing was connected to) |
| `portExposed` | the table in section 5 | stage 2 found the port open |

**Grades are not reused.** ADR 0018's A to F grade is built from vulnerability findings with a fix state; an exposure finding such as a
missing header has no CVE, no fix and no known-exploited flag. A grade would be a number made up of rules that do not mean the same
thing. The page shows **counts by severity** (the fixed colours) and an "attention" filter (open critical or high, a lost verification
or a failed run).

**Colours (rule 6).** Verification is blue ("information") or grey, never green: proving control of a name is no security result. A
valid certificate is plain text. Lost verification is vermilion with an icon. Severity colours are the fixed ones.

### 8. Notifications (ADR 0019)

Four events in the catalogue (group Infrastructure, owners and admins, app and email per the personal matrix, not in the organisation
channels): `exposure.certificate_expiring` (title keys `exposureCertificateExpiring` and `exposureCertificateExpired`; once at 30, 14,
7 days and when expired; a renewed certificate resets), `exposure.verification_lost`, `exposure.new_open_port` and
`exposure.risky_service`. Parameters are the asset name, counts, a port list and a service id; links go to the asset page.

### 9. Data model (migration 0022, additive)

`exposure_settings` (per organisation: the CT switch, who and when, the daily usage), `exposure_asset` (kind, value, include subdomains,
token, verification state and method, stage 2 switch, schedule and acknowledgement, last times and error codes, the two newest snapshots,
the announced certificate step), `exposure_run` (one per look, a unique index on queued or running runs per asset and stage), `exposure_finding`,
`exposure_port` and `exposure_discovery`. No existing table changes. Runs older than the newest 60 per asset and stage are deleted;
findings keep their first and last time; the snapshots hold the latest look only.

### 10. API and roles

`/api/v1/exposure` (additive). Everyone in the organisation reads. Adding, changing, removing, checking and asking for a stage 1 run:
owners and admins (no step-up: adding only starts what a browser does; 60 additions per hour). Switching stage 2 **on**, running it by hand,
creating a new code and switching CT **on**: owners and admins **with a recent sign-in** (step-up); switching stage 2 or CT on also needs the acknowledgement;
switching stage 2 or CT **off** needs no step-up (stopping must be easy). Every change is audited (`exposure.*`). Rate limits: 12 proof
checks, 10 stage 1 runs and 3 manual stage 2 runs per asset and hour. Every query is scoped by organisation; another organisation's
asset is a 404.

### 11. Web

**Infrastructure → Exposure** (navigation, command search for the page, its settings section and each asset): key figures that lead to the
filtered list (more of them from the wide and xwide steps), an assets table (asset and type, verification, counts by severity, stage 1 and
stage 2 status, certificate expiry, location, last check; sortable, filterable, searchable; more columns at wide and xwide, with the
information moved under the name below), the dialogs (Add, Verify with copy buttons and "Check now", Stage 2 with the warning and the
acknowledgement), an asset page (summary cards; findings; DNS, TLS, HTTP, ports and history as tabs below the wide step, findings as a
pane beside the tab from wide, everything side by side from xwide). **Settings → Exposure** holds the CT opt-in. A collapsible help
text on the list says plainly what is and is not done and that it is not legal advice. All text is localised (English and German); all
remote text is rendered as text.

## Threat model

| Threat | What an attacker gains | Mitigation |
| --- | --- | --- |
| **GarnetOps is used as a scanner against third parties** (a typo, a stranger's domain, a malicious insider with admin rights) | Probing hosts one has no right to probe; legal exposure for the customer; the customer's address on someone else's blocklist | Stage 1 is only what a browser does. Stage 2 needs a proof of control (DNS or file), an acknowledgement per asset (audited with the user and the text identifier), a fixed list of 30 ports, 4 at a time, 200 ms apart, once a day at most, and stops the moment the proof or the switch is gone. The proof is re-checked daily and before each run. The documentation and the dialog say that a verified domain does not prove ownership of the infrastructure behind it and that this is not legal advice. **Residual:** an operator who changes the code can fake a proof. Verification is accountability, not a barrier. |
| **SSRF: an asset points at internal targets** (`localhost`, metadata addresses, a name that resolves to 10.x) | Probing the customer's internal network or cloud metadata from the worker | Assets must be public names or addresses; the policy refuses private, loopback, link-local, metadata, shared, documentation and reserved ranges and the mapped, NAT64 and 6to4 forms. The worker resolves, checks **every** answer and connects to the checked address; one non-public answer means no connection at all to that name. Redirect targets are resolved and checked again. |
| **DNS rebinding / split-horizon DNS** | A name that is public at check time and internal at connect time | The checked address is the address that is connected to (no second lookup); the name is only SNI and Host. A name is re-resolved at every run. |
| **A redirect leads somewhere else** (another site, an internal host, another port) | Fetching or probing a target the admin never named | At most 3 redirects, only to the same registrable domain or a verified asset, only on default ports, each target re-checked; the rest is recorded as not followed. The proof file is never fetched through a redirect. |
| **Hostile responses** (banners, headers, certificate names, DNS records) | Stored XSS, log or SQL injection, prompt injection later, memory exhaustion | Everything is cut to a length, stripped of control and bidirectional characters, stored as text and rendered as text (React escapes); banners are 512 bytes, headers come from a fixed list, bodies are read up to 64 KiB and dropped; no remote text becomes a link, Markdown, HTML or part of an AI prompt; tests with `<img onerror>` in every field. |
| **Fake or stale proof** (an attacker reads another organisation's token from public DNS; an old file stays) | Verifying a name one does not control | The token is bound to the organisation and asset and is unguessable (256 bits), so a token read off the internet is useless elsewhere; comparison is exact; the proof is re-checked daily and before each stage 2 run; a definitive loss stops stage 2 at once. |
| **Flaky DNS revokes a good proof, or hides a lost one** | Stage 2 stops for no reason; or runs without a proof | Only a *definitive* loss revokes; an inconclusive check leaves the state; stage 2 fails closed when the last confirmation is older than 48 hours or the live check cannot be made. |
| **Writing to a port (an exploit, a payload, a credential test)** | Harm to a target; abuse of the feature | The code only connects and reads; the socket's `write` is called nowhere; tests with recording listeners assert that plain ports receive zero bytes and TLS ports only handshake records. |
| **Resource abuse of the target** (a flood) | Denial of service of a third party | 4 in flight, 200 ms apart, once a day, 30 ports, 4 addresses, 3 s timeouts, one run per asset at a time, 15-minute tick that queues a bounded number of runs. |
| **Data leaves the network** (CT) | The provider learns which domains are watched | Off by default; exact URL shown; step-up and acknowledgement; audited; verified domains only; budgets; names that come back are suggestions only. Stage 1 and 2 send nothing to a third party. |
| **Untrusted CT answer** | Injection, huge answers, names that point elsewhere | Fixed host over HTTPS with the system store and the address-checked client, no redirects, 4 MiB cap, JSON parsed defensively, only valid names strictly below the domain, at most 500, suggestions only. |
| **A member without rights changes assets, verification or stage 2** | Starting probes, switching on stage 2 | Role checks on every write, step-up for the sensitive ones, organisation scoping on every query, audit log, rate limits. |
| **Cross-tenant data** (one organisation sees another's assets) | Disclosure of what a customer watches | Every query filters by organisation; ids of other organisations answer 404; tested. |
| **The customer's IDS or a provider reacts to stage 2** | Alerts, a blocked address | The documentation and the dialog say stage 2 may be flagged and recommend allowing the installation's address; stage 2 is slow, bounded and off by default. |
| **Wrong conclusions from missing data** | A finding "fixed" because a lookup failed; a banner treated as a vulnerability | Unjudged rules keep their findings; DNSSEC is "not checked"; banners are shown with a note and never matched. |

## Consequences

- GarnetOps gains the outside view with no new dependency (`node:dns`, `node:net`, `node:tls`, `node:https`, `node:url`), no scanner binary
  and no bundled data. The only external service is crt.sh, opt-in, listed in `docs/COMPONENTS.md` as an external data source with
  unconfirmed terms. The worker needs outbound access to the assets (ports 53, 80, 443 for stage 1; the 30 ports for stage 2) and to
  crt.sh if switched on; the Compose stack's `egress` network should allow exactly that.
- **What cannot be tested for real here:** the real internet (a local fake resolver, local HTTPS and TCP servers on loopback and
  throw-away certificates stand in for it), the real crt.sh (a recorded-shape parser test and a refusal test only), a real DB-IP file
  (the GeoIP columns are empty without imported data), real CDNs and cloud load balancers, and the behaviour of other people's intrusion
  detection. TLS 1.0 and 1.1 acceptance is tested for real against a local Node server that offers them.
- **Known limits:** DNSSEC is not checked (Node's resolver interface hides it); the registrable domain is an approximation; the SPF/DMARC
  rules read the policy letters, not the include chain (no recursion, no DNS lookup budget); a name behind a CDN shows the CDN's
  certificate, headers and ports; IPv6-only names are handled but IPv6 reachability of the worker is the operator's business.
- Migration 0022 is additive. Rollback is not needed: nothing runs until an admin adds an asset. Configuration, keys and APIs of earlier
  releases are untouched; the new API is under `/api/v1/exposure` and its fields are never removed within the major version.
- Out of scope, on the roadmap: more ports or custom lists (deliberately not offered), service identification beyond the first bytes, a
  second CT provider, exporting findings, a weekly digest of exposure changes, a grade if a defensible definition appears, IPv6 address
  ranges (single addresses only today), authorisation by an uploaded letter from a hosting provider.
