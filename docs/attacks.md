# Attack overview (Infrastructure, Attacks)

Where do failed logins and attacks on your servers come from? The Attacks page answers that from the
alerts your own Wazuh reports ([xdr.md](xdr.md)), with a globe or a flat world map, a live list of the newest
alerts, tables and, if you switch it on, a reputation score per address. Decisions and the threat model are in
[ADR 0016](adr/0016-attack-overview-local-geoip-and-optional-osint.md) and, for the globe and the live feed, in
[ADR 0021](adr/0021-globe-view-and-live-attack-feed.md).

**What stays local.** Countries and networks are looked up in tables on your own server. Nothing is
sent anywhere for that. Two things can contact the outside, **both off by default**, both switched on by
an owner or admin with a recent sign-in and both audited: the monthly download of the location files and
the optional reputation lookup.

## 1. What you need

1. A **Wazuh connection** ([xdr.md](xdr.md)) **or** the **UniFi IPS preview** ([unifi.md](unifi.md), section 5). The
   Attacks entry appears in the menu, under Infrastructure, only while one of them exists (or UniFi events are still
   stored); without either, the page and Settings say how to connect. With both, their numbers are added up.
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
- **Globe | Map**: a switch above the picture chooses between the **globe** (the default) and the flat world
  map; your choice is remembered in this browser only. Both use country shapes from Natural Earth (public domain),
  shipped with GarnetOps (no tiles, no map service, nothing loaded from outside; the globe is drawn with the
  small library d3-geo). Countries are filled by their alerts in five steps of one colour (blue; never a severity
  colour). Hover for numbers. See sections 3a and 3b for the globe and the home location. **Countries, Networks and Machines** lists beside it
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
  per AS number, never an address, organisation, machine name or rule text. With the UniFi IPS preview it
  also receives the UniFi counts (see below). The answer is labelled "AI suggestion" and is never acted on.

## 3-unifi. UniFi threat events (preview)

When an owner or admin switches on the **IPS preview** for a UniFi console ([unifi.md](unifi.md), ADR 0022), the events
that the gateway detected or **blocked** join the page:

- The numbers, countries, networks and the address table add the UniFi events to Wazuh's. An address that both saw is one
  row. The table shows "N blocked by UniFi" under the count; the country list shows it too.
- On the **globe**, what a console blocked is drawn as a **dashed blue line** (legend **Blocked by UniFi**), next to the orange
  **Observed** lines. Blue is the colour of "information", never a severity colour, and never green: blocking an attack
  proves nothing about the next one. Under reduced motion nothing turns and lines appear at once, as before.
- The **Latest events** list mixes Wazuh alerts and UniFi events in the order they were stored. A UniFi event shows the
  signature, the address, the country, "Blocked by UniFi" or "Observed", the site and the targeted port. A second status
  line says "UniFi IPS preview: live, last event 12 s ago", "waiting for the console" or "paused" (with the reason).
- Signatures and categories are written by whoever attacks you: plain text, never a link, never sent to an AI model.
- **Summarise with AI includes the UniFi events as numbers only.** For each period (24 hours, 7 days, 30 days) the model gets,
  next to Wazuh's figures, the UniFi totals (events, how many the gateway **blocked** and how many it only **alerted**, source
  addresses, and the same figures for the period before) and the counts per **country code** and per **AS number**. The two
  origins are kept apart in what the model sees, because they are counted by different systems and one address can be in
  both; the model is told not to add them up. **Never sent:** an IP address, a signature or category, an organisation name,
  a site, console, device or machine name, a port, a rule group, any other text from an event. The only text in the data are
  our own fixed field names and two-letter country codes. The summary also works with UniFi alone, without a Wazuh
  connection. The question is audited as before (`ai.request`), now naming the origins that fed it (`wazuh`, `unifi`), never data.
- Retention, "Delete stored addresses now" and the home location are the same as for Wazuh. At most 20,000 UniFi events are
  kept per console.

## 3a. The globe

The globe shows the same numbers as the flat map and adds **lines from each source country to your network**.

- **Reading it.** A line starts at the middle of the country (its capital for a country too small for the map)
  and ends at your **home location** (section 3b). A thicker line means more alerts, in three steps; the steps
  are only a hint, the tables have the numbers. A line is **orange** ("Observed"). It is **vermilion** ("High
  abuse score") when the reputation lookup is on and an address of that country has a cached abuse score above 80.
  The ring in the neutral colour is your network. Lines draw in once when the page opens (about a second).
  Without a home location the sources are shown as points and a hint links to the setting.
- **Moving it.** Drag the globe with the mouse or a finger, or focus it (Tab) and use the arrow keys. It turns
  slowly by itself until you touch it, while it has focus, and while the tab is hidden; the button "Pause rotation"
  stops it. If your system asks for **less motion**, the globe does not turn by itself, and lines appear at once.
- **Without a mouse or sight.** The picture has a text alternative that names the busiest countries; the
  Countries, Networks and Machines lists beside it hold the same numbers as tables.
- **Layout.** On a narrow window the globe is above the lists; from 1450 px of content width it is on the left with
  the latest events and the countries beside it; from 1900 px the globe, the events and the lists are three across.

## 3b. Home location (Settings, Attack overview)

Choose the **country** your network is in and, if you like, a **latitude and longitude** (two decimals, about a
kilometre; typed by hand, or "Use the capital"). With a country only, lines end in its capital. There are **no
default coordinates**: until someone sets a home location, the globe shows points and no lines. Owners and admins
set or remove it; everybody in the organisation sees the result. It is audited (`attacks.home_changed`,
`attacks.home_removed`) and nothing is sent anywhere.

## 4. Latest events (live feed)

"Latest events" lists the newest alerts as Wazuh reports them, newest first, at most 50: country code, the rule
description, the source address as plain text, the country, "observed", the machine, the rule level, how long
ago, and the abuse score when the reputation lookup is on and a score is cached (the feed never triggers a
lookup by itself). Every new event also draws a line on the globe, which fades after a few seconds. The same list
is on the XDR page as "Latest alerts".

- **How it works.** The worker asks your Wazuh indexer, read-only, every **30 seconds** (Settings, Attack
  overview, Live feed: 15 to 300 seconds, and the lowest rule level, 3 to 15, default 7). One request reads at
  most 50 alerts and only the fields the list shows: time, rule, level, description, groups, machine, and source
  address; **never the log line**, the source port or the user name that was tried. GarnetOps polls; Wazuh
  never calls GarnetOps, and nothing is written to Wazuh. Details and limits: [xdr.md](xdr.md) and
  [ADR 0021](adr/0021-globe-view-and-live-attack-feed.md).
- **Browsers** are told through a server-sent event stream that resumes after a break. If the stream cannot be
  opened, the page says so and refreshes the list every 30 seconds.
- **The line above the list** says what is true: "Live — last event 12 s ago", "Live — no events yet",
  "Waiting for Wazuh" (no sync or poll yet, the last poll failed, with the reason, or the worker has gone quiet),
  "Paused: connection blocked" (the Wazuh connection is switched off, a certificate has to be confirmed again, or
  privileges have to be acknowledged: it says which) or "The live feed is switched off". The totals above keep
  their own time, "Wazuh data from …", because they come from the 15-minute sync.
- **A window, not a log.** Alerts that Wazuh makes searchable late can be missed, and nothing is kept as history:
  the newest 500 events per connection are stored, and none for longer than the retention period (section 5).
  The numbers, tables and the AI summary come from the aggregates, never from this list.
- **Hostile text.** The rule description and the machine name come from alerts that someone else may have
  written. They are cleaned, cut to 200 and 128 characters, shown as plain text, never as a link or markup and
  never sent to an AI model.

## 5. Keeping source addresses (privacy)

Source addresses can be personal data. GarnetOps keeps only the **latest aggregate of each period**,
replaced at every sync, and builds no history. As a backstop, an hourly job deletes source addresses, attack
figures and reputation results older than the **retention period** (default **90 days**, 1 to 365, in
Settings; raising it needs a recent sign-in). Normally nothing gets that old; it matters when the sync stops
or you shorten the period. "Delete stored addresses now" (recent sign-in, audited) erases them at once for an
erasure request, and removing the Wazuh connection deletes them too. The audit log holds counts, never
addresses. The **latest events** of the live feed are source addresses too: they follow the same retention period,
"Delete stored addresses now" deletes them, and removing the Wazuh connection deletes them with it. Describe this
processing in your own records of processing if GDPR applies to you.

## 6. Reputation lookup (optional, off by default)

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

## 7. Roles

| Action | Roles | Recent sign-in |
| --- | --- | --- |
| Read the page, tables and summary | everyone in the organisation | no |
| Ask for an AI summary | member and above | no |
| Settings, import or remove location data | owner, admin | yes |
| Monthly download on | owner, admin | yes (off: no) |
| Retention longer | owner, admin | yes (shorter: no) |
| Delete stored addresses (also the latest events) | owner, admin | yes |
| Reputation lookup on, key, provider | owner, admin | yes (off: no) |
| Home location | owner, admin | no |
| Live feed on or off, interval, lowest rule level | owner, admin | no |
| Read the latest events and the stream | everyone in the organisation | no |

All changes are in the audit log (filter "Attacks"): `attacks.geoip_imported`, `attacks.geoip_import_failed`,
`attacks.geoip_removed`, `attacks.geoip_downloaded`, `attacks.geoip_download_failed`,
`attacks.geoip_download_enabled`, `attacks.geoip_download_disabled`, `attacks.settings_changed`,
`attacks.osint_enabled`, `attacks.osint_disabled`, `attacks.osint_key_changed`, `attacks.osint_key_removed`,
`attacks.data_purged`, `attacks.home_changed`, `attacks.home_removed`, `attacks.live_feed_changed`.

## 8. Troubleshooting

| What you see | What to do |
| --- | --- |
| Attacks is not in the menu | There is no Wazuh connection yet: Settings, XDR / Wazuh. |
| "No attack data yet" | Wait for the next Wazuh sync, or run one from the XDR page. |
| Every country is "Unknown" | No location data is loaded: Settings, Attack overview. |
| "The location data is old" | Load this month's files, or switch on the monthly download. |
| The globe shows points but no lines | No home location is set: Settings, Attack overview, Home location. |
| "Waiting for Wazuh" under Latest events | The sync has not run yet, or the last request failed (the reason is shown); check the connection on the XDR page. |
| "Paused: connection blocked" | Confirm the changed certificate or acknowledge the privileges: Settings, XDR / Wazuh. |
| "The live feed is switched off" | Switch it on: Settings, Attack overview, Live feed. |
| The globe does not turn | Your system asks for less motion, you moved it, or it has focus. "Turn slowly" starts it again (not under less motion). |
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
