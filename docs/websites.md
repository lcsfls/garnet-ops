# Website monitoring

**Infrastructure → Websites** watches your own public domains, host names and IP addresses from the outside:
which certificate is about to expire, which security headers are missing, whether mail authentication is set up,
and, for assets you verified, which common ports answer from the internet (ADR 0023, ADR 0033).

## Switch the module on

Website monitoring is a module and is **off by default**: once it is on, GarnetOps connects from your installation to the public
hosts you add. Owners and admins see **Infrastructure → Websites** in the menu all along and switch the module on right there, or
under **Settings → Modules → Website monitoring**. Until then nothing is looked at, other members do not see the entry, and the API
answers `409 module-off`.

Once it is on, the **+** next to **Websites** in the menu adds a website, and the menu counts the websites that need a look (the
**Needs attention** filter of the list: an open critical or high finding, a lost verification, a failed check).

Switching it off again keeps your websites, findings and history, but switches stage 2 off for every website (each needs a new
confirmation later) and drops checks that were still waiting. Both are in the audit log.

Everything runs from **your own GarnetOps installation**. Nothing about your assets is sent to GarnetOps or to anyone else,
with one optional exception that is off by default (Certificate Transparency, below).

> **This is not legal advice.** GarnetOps is self-hosted and you are responsible for what you check. Look only at names and
> addresses you own or have permission to test. A verified domain proves that you control its DNS; it does **not** prove that
> you own the servers, CDN, shared host or cloud service behind it. Ask whoever runs that infrastructure before you switch on
> stage 2.

## Two stages

| | Stage 1: from outside | Stage 2: light active checks |
| --- | --- | --- |
| What | DNS records, the TLS certificate and protocols, one request for the home page | Opens a TCP connection to a fixed list of 30 common ports and reads what a service sends first |
| Needs | Nothing: it is what any browser or mail server does | A verified asset **and** your confirmation per asset |
| Default | On for every asset, daily and on request | Off |
| Roles | Everyone reads. Owners and admins add and check | Owners and admins, with a recent sign-in |

### What is never done

No exploits, no password or credential testing, no brute force, no fuzzing, no flooding, no crawling, no form submission and no
payloads. Stage 2 **only connects and reads**: apart from the TLS handshake on TLS ports, nothing is written to a port. There is
no raw-socket or SYN scanning and no third-party scanner. Subdomains are never guessed.

## Add an asset

**Websites → Add asset.** Enter a domain, a host name or a single public IP address:

- A host name follows RFC 1123 (letters, digits, hyphens; two or more parts; `www.example.com`). No URL, path, port, wildcard or user name.
  Names ending in `.local`, `.lan`, `.internal` and similar are refused because they are not public.
- An address must be public. Private (10.x, 172.16-31.x, 192.168.x), loopback, link-local (including cloud metadata
  169.254.169.254), shared (100.64.0.0/10), documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) and
  reserved addresses are refused.
- Up to **200 assets** per organisation. A name that is already on the list is refused.
- **Include subdomains** (domains only, off by default): while the domain is verified, its subdomains count as verified.

Adding an asset starts stage 1 at once, and then every day.

## Verify an asset

Stage 2 only runs for assets whose control you proved. Right after you add an asset, its page opens with this dialog; later you
find it under **Websites → the asset → Verify…**. Publish **one** of these:

**A DNS record** (domains and host names). Add a TXT record:

```text
Name:   _garnetops-challenge.www.example.com
Type:   TXT
Value:  garnetops-verify=<your code>
```

**A file** (domains, host names and addresses). Serve the same text at

```text
https://www.example.com/.well-known/garnetops-verify.txt
```

The file may contain the bare code or `garnetops-verify=<code>` on a line of its own. Names are fetched over HTTPS with a valid
certificate. An address is tried over HTTPS and then plain HTTP. **Redirects are not followed**, and the file must be at most 1 KiB.

Press **Check now**. The worker looks up the proof and the dialog shows the result: the proof was found, or why not (record
missing, record with another value, file missing, file without the code, file redirected, certificate refused, ...). A check can
be started twelve times an hour per asset; GarnetOps also checks once a day.

The worker asks for the TXT record both through the system resolver and **directly at the domain's own name servers** (only at
public addresses, one TXT query each). That way a new record counts at once, even if a resolver in your network still remembers
the "not there" of an earlier check, or answers for your own domain from an internal zone. Where outgoing DNS (port 53) is blocked,
the system resolver alone decides, as before.

## Software versions

The daily look also notes what a site says about its own software: `Server` (nginx, Apache), `X-Powered-By` (PHP) and the
`<meta name="generator">` tag of the home page (WordPress, Drupal, Joomla, TYPO3, MediaWiki, Astro). Each version is judged
against the end-of-life data of [endoflife.date](https://endoflife.date) that ships with GarnetOps (no request at run time; the
data is refreshed with every release, [ADR 0038](adr/0038-website-software-versions.md)):

- **Software without security fixes**: its release line has ended (for example PHP 8.1 after 31 December 2025).
- **Software behind its latest version**: a newer version of the same line exists, which may fix known vulnerabilities.

A CMS names its own version exactly, so it counts fully. A server header counts one step lower, and a header that names a
distribution (`Apache/2.4.57 (Debian)`, `PHP/8.1.2-1ubuntu2.14`) is shown but not judged: distributions fix security problems
without changing the number. The HTTP section of a website lists what was found and how it was judged.

**WordPress themes and plugins** ([ADR 0042](adr/0042-wordpress-plugins-and-themes.md)): the HTTP section also lists the themes
and plugins the home page's asset addresses name (`/wp-content/plugins/<slug>/…`), with the version the address carries. Plugins
that load nothing on the home page are not seen, and nothing else of the site is requested.

To judge them, an owner or admin can switch on **Latest versions of WordPress plugins and themes** under Settings → External services
(off by default). GarnetOps then asks api.wordpress.org once a day for the latest version of each slug: only the slug is sent, no
website name, version or organisation. A plugin or theme behind its latest version becomes the finding **WordPress plugin or
theme behind its latest version** (low: the version is the one an asset address names). Premium and custom plugins that
wordpress.org does not list are shown as such and not judged.

**Known vulnerabilities from Wordfence** (optional, your own key): an owner or admin can set a Wordfence Intelligence API key
under Settings → External services (create one in your Wordfence account under Integrations). GarnetOps then downloads the
Wordfence vulnerability feed once a day with that key, keeps only the advisories for the WordPress versions, plugins and themes
your websites show, and reports each shown version inside an advisory's affected range as **Known vulnerability in …**, with the
advisory's CVSS rating, the CVE and the fixed versions. Only the key is sent, nothing about your websites; it is encrypted at once
and never shown again. Removing the key deletes the downloaded advisories. Use of the feed is governed by the Wordfence
Intelligence terms, which you accept when setting the key.

## The report

A website opens on its **Report**: every area that is checked, in one list, with a plain state each: availability, certificate
and TLS, HTTPS, security headers, software versions, mail authentication, DNS records, DNSSEC and open ports (mail, DNS and DNSSEC
only for names). An area with open findings shows the worst severity and the worst finding's title; an area without shows
**No problems found**; an area that is switched off or was not looked at yet says so. Selecting an area opens its details. The
report adds no checks of its own: it sums up the findings and results of the other tabs.

## Availability

On the **Availability** tab of a website an owner or admin can switch on a check every 1, 5, 15 or 60 minutes
([ADR 0040](adr/0040-website-availability.md)). It is off for every asset until switched on. The check is the request stage 1
makes anyway: one `GET /` over HTTPS to a public address of the asset, with the certificate verified, reading only the status and
headers.

- **Answering**: the server sent a status below 500 (a redirect, 401 or 404 counts: the server answered).
- **Down**: three checks in a row failed: no answer within 10 seconds, connection refused, TLS handshake failed (also an invalid
  certificate), not an HTTP answer, the name does not resolve or resolves only to non-public addresses, or a 5xx status. The first
  successful check makes it answering again.
- **Slow**: answers took more than 3 seconds on average in the last 24 hours. The site is up, but this often points to a hosting
  problem.

The tab shows the shares of successful checks for 24 hours, 7 and 30 days with the average answer time, the last 24 hours hour by
hour, and the outages. Checks are kept 30 days. A website that is down is listed under **Needs attention** and counted in the menu.
The checks run from your GarnetOps installation: a site blocked only for its network shows as down.

## A slow local resolver

If your own resolver (a firewall or router) answers slowly, checks run into time-outs and report "DNS failed". Under
**Settings → External services → Public DNS for public names** an owner or admin can add Cloudflare (1.1.1.1), Google (8.8.8.8) or Quad9
(9.9.9.9) next to your own resolver: each lookup goes to both, the first clear answer counts
([ADR 0035](adr/0035-public-dns-for-public-names.md)). It applies only to lookups of public names (website checks, the proof,
registry checks, Certificate Transparency); forges, directory sign-in, mail and the AI endpoint keep using only your own resolver.
It is off by default, because the names looked up go to the provider; choosing one needs a recent sign-in and an acknowledgement,
and is audited.

About the code:

- It is 256 random bits, created for this asset in your organisation only. It is **not a secret**: you publish it. It is shown in
  the dialog whenever an owner or admin opens it. What makes it proof is that nobody can guess it and that it belongs to one asset
  of one organisation.
- **New code** voids the old proof, marks the asset not verified and switches stage 2 off (recent sign-in required).

The proof is checked **every day** and again **before every stage 2 run**. If it disappears, stage 2 stops at once for the asset,
the acknowledgement is void, owners and admins get the notification "Verification lost", and the audit log has an entry. A lookup
that merely fails (a DNS outage, a timeout) does not revoke a good proof, but stage 2 does not run unless a proof was confirmed in
the last 48 hours.

A verified domain with **Include subdomains** also covers its subdomains. Each subdomain still needs its own confirmation for stage 2.
If the domain loses its proof, or the option is switched off, or the domain is removed, stage 2 stops for the subdomains too.

## What stage 1 looks at

For each asset, daily:

- **DNS** (domains): A, AAAA, CNAME, MX, NS, CAA, the SPF record, the DMARC policy. Reverse names for addresses.
- **DNSSEC** (domains, [ADR 0036](adr/0036-dnssec-monitoring.md)): the zone's DS records at the parent, its DNSKEY records and the
  signatures over the keys and over the SOA record, asked directly of the name servers and checked by GarnetOps itself (RSA, ECDSA
  P-256 and P-384, Ed25519, Ed448). The DNS section shows the state, the keys, the DS records and until when the signatures hold.
- **TLS on port 443**: certificate chain and expiry, names, key, the protocol and cipher a modern client gets, and whether the
  server still accepts **TLS 1.0 and TLS 1.1** (two extra handshakes that send no data).
- **HTTP**: one `GET /` over HTTPS and one over plain HTTP on port 80. Redirects are followed at most 3 times, only to the same
  registrable domain or to another verified asset, only on the default ports. Status, final address and the security headers are
  kept; the page itself is read up to 256 KiB and **never stored**.

If a name resolves to an address that is not public, GarnetOps **connects to nothing for that name** and says so.

### Findings

Plain rules. The severity says how unusual or risky a finding is, not that you are being attacked.

| Rule | Severity | Meaning |
| --- | --- | --- |
| Certificate expired | high | Browsers refuse it |
| Certificate expires soon | high, medium, low | 7, 14, 30 days left |
| Certificate not trusted / for another name | medium | The chain or the name does not verify (self-signed certificates end up here) |
| Weak certificate key | medium | RSA below 2048 bits |
| Old TLS versions accepted | medium | TLS 1.0 or 1.1 still works |
| No HSTS / HSTS shorter than 180 days | low | |
| No Content-Security-Policy, X-Content-Type-Options, framing protection, Referrer-Policy or Permissions-Policy | low | One finding per header |
| Server names a version | low | The `Server` or `X-Powered-By` header shows e.g. `nginx/1.22.1` |
| Software without security fixes | high for a CMS's own version, medium from a server header | The release line has ended ([ADR 0038](adr/0038-website-software-versions.md)) |
| Software behind its latest version | medium for a CMS, low from a server header | A newer version of the same line exists |
| Plain HTTP does not redirect to HTTPS | medium | Port 80 answers with content |
| Only plain HTTP is offered | medium | Nothing speaks HTTPS on 443 |
| No SPF record / no DMARC policy | medium with a mail server (MX), otherwise low | |
| SPF allows everyone (`+all`, `?all`) / several SPF records | medium | |
| DMARC only monitors (`p=none`) | low | |
| No CAA record | low | |
| CNAME to a name that does not resolve | medium | A takeover risk if someone else can register that name |
| Resolves to a non-public address | low | Nothing was connected to |
| DNSSEC broken | high | A DS record names no key, a signature does not check out or has run out: validating resolvers answer with an error for the whole domain |
| DNSSEC signatures run out within a day | medium | Live signers keep days ahead; less than a day left means signing has stopped |
| Zone signed, but no DS record at the parent | medium | Resolvers treat the zone as unsigned until the registrar has the DS record |
| Outdated DNSSEC algorithm | medium | RSA/SHA-1 and older (RFC 8624) |
| DNSSEC not set up | low | |
| DS records with SHA-1 only | low | |

**About banners.** A version in a `Server` header is shown as a fact with the advice to check whether it is current. GarnetOps does
**not** match banner versions against vulnerability data: Debian, Red Hat and other distributions fix security problems in older
versions without changing the number, so such a match would be wrong in both directions.

A finding stays open while the rule fires and is resolved when it stops. A lookup that failed leaves the findings of its rules as they
are: "could not look" is not "fixed".

## Stage 2: light active checks

**Websites → the asset → Switch on…** (owners and admins, recent sign-in). The dialog shows what the stage does and never does and
the warning about the infrastructure behind a name. You tick "I am authorised to test the infrastructure behind this name"; your name,
the time and the version of that text go into the audit log.

What it does, with limits that are enforced in the code:

- Connects to each of **30 fixed ports** of every public address of the name (at most four addresses). The list cannot be changed.
- At most **4 connections at a time**, at least **200 ms** between the starts of two, **3 seconds** to connect.
- **At most once per 24 hours per asset**, daily or weekly, whoever asks (the schedule or a person).
- Where a service speaks first (SSH, SMTP, FTP, IMAP, POP3) it waits up to 2 seconds and keeps up to 512 bytes as plain text.
- On TLS ports it makes a TLS handshake and reads the certificate. On every other port it connects and closes.
- Before every connection it checks again that the asset is still switched on, acknowledged and covered by a fresh proof. If not,
  the run stops and stores nothing.

| Port | Service | Severity if open |
| --- | --- | --- |
| 21 | FTP | medium |
| 22 | SSH | usual |
| 23 | Telnet | high |
| 25 | SMTP | usual |
| 53 | DNS over TCP | usual |
| 80 | HTTP | usual |
| 110 | POP3 | low |
| 143 | IMAP | low |
| 443 | HTTPS | usual |
| 445 | SMB | high |
| 465 | SMTP over TLS | usual |
| 587 | Mail submission | usual |
| 993 | IMAP over TLS | usual |
| 995 | POP3 over TLS | usual |
| 1433 | Microsoft SQL Server | high |
| 1521 | Oracle | high |
| 2375 | Docker API, no TLS | critical |
| 2376 | Docker API, TLS | medium |
| 3000 | Development server | low |
| 3306 | MySQL / MariaDB | high |
| 3389 | Remote Desktop | high |
| 5432 | PostgreSQL | high |
| 5900 | VNC | high |
| 6379 | Redis | high |
| 8000 | HTTP, alternative port | low |
| 8080 | HTTP, proxy or alternative port | low |
| 8443 | HTTPS, alternative port | usual |
| 9200 | Elasticsearch | high |
| 11211 | Memcached | high |
| 27017 | MongoDB | high |

The severity says how unusual it is to see the service open to the internet. GarnetOps sends nothing, so it cannot tell whether the
service is protected.

A port that is open now and was not in the previous successful run is **new** and you are notified (the first run is the baseline).
A high or critical service notifies once while it stays open.

### Your own intrusion detection

Your firewall, IDS or hosting provider may flag these connections as a port scan. They come from the **address of the machine that
runs the GarnetOps worker**. If you do not want alerts, allow that address for the target. The run is slow on purpose (about
6 seconds per address for the connections alone, plus up to 2 seconds for each service that speaks first).

## Certificate Transparency (optional)

Public certificate logs list every certificate that was issued. Asking them finds subdomains you may have forgotten. It is **off by
default**, because it sends the domain names of your verified assets to a public search service (**crt.sh**, operated by Sectigo).

**Settings → External services → Certificate Transparency → Switch on** (owners and admins, recent sign-in). The dialog shows the exact request,
`https://crt.sh/?q=%25.{domain}&output=json&exclude=expired`, and asks you to confirm that you understand what is sent. Limits: only
domains that proved control themselves, once a day per domain, at most 100 queries a day, one every 10 seconds, answers capped at
4 MiB. The names it finds are **suggestions** on the asset page under "Names found"; nothing connects to them until you press
**Add as asset**.

crt.sh publishes no terms or service level for this use that GarnetOps could confirm. Check them yourself before you switch this on.
Switching it on and off is in the audit log.

## Notifications

Under **Account → Notifications** (owners and admins; in the app and, if you want, by mail):

- **An exposed certificate expires soon**: once at 30, 14 and 7 days, and when it has expired. A renewed certificate starts again.
- **An asset lost its verification**: once.
- **A new port is open on an asset**: ports open now that were not open in the previous successful stage 2 run.
- **A risky service is reachable from the internet**: a high or critical port, once while it stays open.

For every member (in the app and, if you want, by mail):

- **A website is down or back up**: once when an asset with the availability check turns down, and once when it answers again.

They link to the asset. They carry the asset name, counts and a list of ports, never banners or headers.

## Roles and the audit log

| | Viewer, member | Admin, owner |
| --- | --- | --- |
| See assets, findings, results | yes | yes |
| Add, change, remove, verify, check now | no | yes |
| Switch stage 2 on, run it by hand, new code, Certificate Transparency or the wordpress.org lookup on | no | yes, with a sign-in from the last ten minutes |
| Switch stage 2, Certificate Transparency or the wordpress.org lookup off | no | yes |
| Switch the availability check on or off | no | yes |

The audit log (filter **Websites**) has: asset added and removed, verified, verification lost and restored, verification code
replaced, stage 2 switched on (with the acknowledgement), off, stopped and run by hand, subdomain coverage changed, Certificate
Transparency switched on and off, wordpress.org lookup switched on and off, Wordfence key set, replaced and removed, availability check switched on (or its interval
changed) and off.

## Limits and what is not tested

- Up to 200 assets per organisation; the newest 60 runs per asset and stage are kept.
- DNSSEC is checked for the zone, not for every name in it, and denial of existence (NSEC, NSEC3) is not checked. When the name
  servers cannot be asked (outgoing DNS on port 53 blocked), DNSSEC shows "not checked" and its findings stay as they were.
- The registrable domain used for redirects and DMARC is an approximation without the public suffix list.
- SPF is judged by its final policy; includes are not followed.
- A name behind a CDN shows the CDN's certificate, headers and ports.
- Tested with local servers on loopback, throw-away certificates and a fake resolver; **not** against the real internet, real CDNs,
  the real crt.sh or someone else's intrusion detection.

## API

`/api/v1/exposure` (the paths of 0.0.3, back in 0.0.12; additive, fields are never removed within a major version; 409
`module-off` while the module is off). The switch itself is `GET /api/v1/organization/modules` and
`PUT /api/v1/organization/modules/websites` (`{ enabled }`, owners and admins). `GET /` (filters `q`, `status`, sort and cursor),
`GET /counts`, `GET /:id`, `POST /` (`{ value, includeSubdomains }`), `PATCH /:id`, `DELETE /:id`, `POST /:id/verify`,
`POST /:id/verify/rotate`, `POST /:id/run`, `PUT /:id/uptime` (`{ enabled, intervalMinutes }`), `PUT /:id/stage2`, `POST /:id/stage2/run`, `GET` and `PUT /settings`,
`POST /discoveries/:id/add` and `/dismiss`. Errors are RFC 9457 problem documents (`duplicate`, `limit-reached`, `not-verified`,
`too-soon`, `step-up-required`, `validation` with the reason of each refused field).
