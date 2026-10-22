# Attack overview (Infrastructure, Attacks)

Where do failed logins and attacks on your servers come from? The Attacks page answers that from the
alerts your own Wazuh reports ([xdr.md](xdr.md)), with a world map, tables and, if you switch it on, a
reputation score per address. Decisions and the threat model are in
[ADR 0016](adr/0016-attack-overview-local-geoip-and-optional-osint.md).

**What stays local.** Countries and networks are looked up in tables on your own server. Nothing is
sent anywhere for that. Two things can contact the outside, **both off by default**, both switched on by
an owner or admin with a recent sign-in and both audited: the monthly download of the location files and
the optional reputation lookup.

## 1. What you need

1. A **Wazuh connection** ([xdr.md](xdr.md)). The Attacks entry appears in the menu, under Infrastructure,
   only while one exists; without it the page and Settings say how to connect.
2. **Location data** from DB-IP, loaded once (and refreshed monthly): see section 2. Without it the page
   still lists the addresses, but every country and network is "Unknown".

The data comes from the Wazuh sync (every 15 minutes): the 100 busiest source addresses of the rule groups
for failed logins and attacks (`authentication_failed`, `authentication_failures`, `invalid_login`, `attack`,
`attacks`, `web_scan`, `recon`, `sql_injection`, `exploit_attempt`, `automatic_attack`) for 24 hours, 7 and
30 days.

## 2. Location data (Settings, Attack overview)

GarnetOps uses two free files from [DB-IP](https://db-ip.com), **IP to Country Lite** and **IP to ASN
Lite** (CSV, gzip, updated monthly). They are licensed **CC BY 4.0**; the page shows the required
attribution, "IP geolocation by DB-IP (db-ip.com), CC BY 4.0". GarnetOps does **not** ship the data
and never puts it in the repository or an image.

File names: `dbip-country-lite-YYYY-MM.csv.gz` and `dbip-asn-lite-YYYY-MM.csv.gz`. Lines look like
`198.51.100.0,198.51.100.255,DE` (country) and `198.51.100.0,198.51.100.255,64500,"Example Hosting"`
(ASN), IPv4 and IPv6 together, sorted, without overlaps.

### Manual import (works without internet on the server)

Download the two files on any computer, then Settings, Attack overview, Location data: choose the file
for Country and for Network and press Import. (Owners and admins; needs a recent sign-in.)

- The file is streamed and checked while it arrives: at most **64 MiB** compressed and **256 MiB**
  unpacked, lines of at most 1 KiB, at most 3 million ranges, ranges ascending and not overlapping.
  A file that is not gzip, damaged, empty, the wrong kind (a country file in the ASN slot) or mostly
  invalid is refused with the reason.
- The new data replaces the old **only when the whole file passed**. If anything is wrong, the data you
  have stays, and the page says why the last attempt failed.
- The release month is read from the file name and shown, with the number of ranges and the source
  (manual import or monthly download). The page warns when the data is more than three months old.

### Monthly download (opt-in)

Tick "Download the files from DB-IP every month". The page shows the exact addresses:

```
https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz
https://download.db-ip.com/free/dbip-asn-lite-YYYY-MM.csv.gz
```

Only the worker connects, only to `download.db-ip.com`, over HTTPS with a verified certificate. It checks
that the name resolves to **public** addresses only, follows **no redirects**, limits size and time, and
applies the same checks and the same replace-only-when-valid rule as a manual import. It asks for this
month's file (last month's if DB-IP has not published it yet), at most every 12 hours, and does nothing once
the month is loaded. The two ports to allow in a restricted `egress` network: 443 to `download.db-ip.com`.
Switching the option off stops all requests at once.

If DB-IP ever answered with a redirect, the download would fail and say so; the manual import still works.

## 3. The page

- **Period**: 24 hours, 7 days, 30 days (in the URL).
- **Key figures** with the change against the period before: attack alerts, source addresses (approximate),
  countries, the most targeted machines; more figures (alerts from inside, location unknown) on wide
  screens.
- **Map**: country shapes from Natural Earth (public domain), plain SVG shipped with GarnetOps (no tiles, no
  map library, nothing loaded from outside). Countries are filled by their alerts in five steps of one colour
  (blue; never a severity colour). Hover for numbers. **Countries, Networks and Machines** lists beside it
  hold the same numbers as a table, are complete (a few small countries have no shape on the map) and are the
  keyboard and screen reader route; choosing one filters the address table.
- **Address table**: address (plain text with a copy button, never a link), country, network (AS number and
  organisation), alerts, rule groups, the machines attacked (linked to Servers when the agent is linked to a
  server, otherwise to XDR), first and last seen, and the reputation score when that is switched on. Sort by
  any marked column; filter by country (also "Internal" and "Unknown"), rule group, network and machine;
  search; 25, 50 or 100 per page. Everything is in the URL.
- **Internal** addresses (private, shared, loopback, link-local, reserved) are labelled so and are never
  looked up or sent anywhere.
- **Approximate**: a country here means "this address range is registered or used there". It does not say
  where a person is, and VPNs, proxies and hacked machines are common. The page says so.
- **Coverage**: the lists cover the 100 busiest addresses of a period ("105 of 120 alerts"); the key figures
  for alerts and sources count all.
- **Summarise with AI** (only when AI is set up and on): the model receives numbers per country code and
  per AS number, never an address, organisation, machine name or rule text. The answer is labelled "AI
  suggestion" and is never acted on.

## 4. Keeping source addresses (privacy)

Source addresses can be personal data. GarnetOps keeps only the **latest aggregate of each period**,
replaced at every sync, and builds no history. As a backstop, an hourly job deletes source addresses, attack
figures and reputation results older than the **retention period** (default **90 days**, 1 to 365, in
Settings; raising it needs a recent sign-in). Normally nothing gets that old; it matters when the sync stops
or you shorten the period. "Delete stored addresses now" (recent sign-in, audited) erases them at once for an
erasure request, and removing the Wazuh connection deletes them too. The audit log holds counts, never
addresses. Describe this processing in your own records of processing if GDPR applies to you.

## 5. Reputation lookup (optional, off by default)

Shows an abuse score next to the busiest public addresses, from **AbuseIPDB** (check API), with **your own API
key**. **When it is on, public source addresses leave your network**: the busiest ones, at most N per sync
(default 20, at most 50), within a daily request budget (default 300, at most 900, always below AbuseIPDB's free
limit of 1,000 checks a day), results reused for 24 hours. **Private addresses are never sent.** Only the
worker calls the provider, over HTTPS to `api.abuseipdb.com`, without following redirects.

To switch it on (owner or admin, recent sign-in): enter the key, set the two limits and confirm both
statements, "public source addresses are sent to AbuseIPDB" and "I have checked that the terms of AbuseIPDB
allow this use with my key". The key is sealed in the vault, never shown again and never written to a log or the
audit log. Switching it off, replacing the key or removing it deletes the stored scores. The table then shows the
score, the number of reports and the last report; the only link to the outside is to AbuseIPDB's page for that
address (`rel="noopener noreferrer nofollow"`, new tab), and only while the lookup is on.

**Terms of use.** We could not read AbuseIPDB's terms while building this, and the maintainers have not
confirmed that your plan allows this use (its free plan is commonly offered for non-commercial use; check
your own agreement, and use a paid plan if you are a business). That is why the confirmation is yours to
give and the page links to the terms. The feature is built around a small provider interface
(`packages/core/src/osint.ts`); a provider whose terms are unclear can be added and left switched off.

## 6. Roles

| Action | Roles | Recent sign-in |
| --- | --- | --- |
| Read the page, tables and summary | everyone in the organisation | no |
| Ask for an AI summary | member and above | no |
| Settings, import or remove location data | owner, admin | yes |
| Monthly download on | owner, admin | yes (off: no) |
| Retention longer | owner, admin | yes (shorter: no) |
| Delete stored addresses | owner, admin | yes |
| Reputation lookup on, key, provider | owner, admin | yes (off: no) |

All changes are in the audit log (filter "Attacks"): `attacks.geoip_imported`, `attacks.geoip_import_failed`,
`attacks.geoip_removed`, `attacks.geoip_downloaded`, `attacks.geoip_download_failed`,
`attacks.geoip_download_enabled`, `attacks.geoip_download_disabled`, `attacks.settings_changed`,
`attacks.osint_enabled`, `attacks.osint_disabled`, `attacks.osint_key_changed`, `attacks.osint_key_removed`,
`attacks.data_purged`.

## 7. Troubleshooting

| What you see | What to do |
| --- | --- |
| Attacks is not in the menu | There is no Wazuh connection yet: Settings, XDR / Wazuh. |
| "No attack data yet" | Wait for the next Wazuh sync, or run one from the XDR page. |
| Every country is "Unknown" | No location data is loaded: Settings, Attack overview. |
| "The location data is old" | Load this month's files, or switch on the monthly download. |
| Import refused: "not a gzip file" | Choose the `.csv.gz` file as downloaded, not an unpacked or renamed one. |
| Import refused: "other kind of file" | The country file belongs in Country, the ASN file in Network. |
| Download failed: "not found" | DB-IP has not published this month's file yet; GarnetOps tries again. |
| Download failed: "redirect" or "certificate" | A proxy or firewall is in the way; use the manual import. |
| Reputation lookup: "key rejected" | The API key is wrong or revoked: replace it. |
| Reputation lookup: "daily limit reached" | The budget for today is used; it starts again at midnight UTC. |

## 8. Limits

- Locations are approximate and based on one free dataset; ASN organisation names come from the same file.
- The page shows the latest aggregates only, no history of attacks over time (by design).
- The top 100 addresses of a period are listed; countries and networks are counted from those.
- Not tested against a real DB-IP file or the real AbuseIPDB service (synthetic fixtures with documentation
  address ranges and local test servers only), and not against a real Wazuh installation.
- GarnetOps only reads: it blocks nothing and reports nothing to anyone.
