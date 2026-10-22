# UniFi

**Infrastructure → Servers → Network devices** shows the devices of your UniFi consoles next to your
servers: gateways, switches and access points with their model, address, state, firmware version
and uptime, per site. It tells you which devices are offline and for which a newer firmware
exists (ADR 0022). An optional **preview** also shows what your gateway's intrusion prevention
(IPS) detected and blocked on the Attacks page and its globe.

**GarnetOps only reads, and only locally.** It talks to the *official local UniFi Network API* of
your own console, over HTTPS, with `GET` requests to a short list of endpoints. It never
restarts, adopts, upgrades, renames or changes anything. **It never uses the Ubiquiti cloud**
(the Site Manager API at `api.ui.com`): that would send your inventory to a third party, and
GarnetOps has no code for it. No Ubiquiti code or library is part of GarnetOps.

Everyone in your organisation can see the devices. Owners and admins connect and manage consoles
under **Settings → UniFi**.

## What you need

- A UniFi OS console (UDM, UDM Pro, UCG, Cloud Key Gen2 and newer, …) or a self-hosted UniFi Network
  Application, version **9.0 or newer** (the version that has the official local API).
- Network access **from the GarnetOps worker to the console on port 443** (UniFi OS) or the port of
  the Network Application (usually 8443). See Firewall below.
- Someone with administrator rights on the console, once, to create an API key (and, for the
  preview, a user).

## 1. Create an API key on the console

1. Open the console's web interface and go to **Settings → Control Plane → Integrations**.
2. Create an API key (any name, for example `GarnetOps`) and copy it. The console shows it only once.

**What the key can do.** Ubiquiti does not offer read-only keys. A key has the permissions of the
whole official local API, which includes actions such as restarting a device. GarnetOps sends read
requests only (this is enforced in the client, not just promised), but treat the key like a password:
it is sealed in GarnetOps' vault, only the worker can open it, and you cut the access at any time
by deleting the key on the console.

## 2. Connect the console

**Settings → UniFi → Add console.**

1. Enter a name, the **console address** (`https://udm.example.lan`; https only; add the port if it is
   not 443), the **API key**, and the **kind of console**: *UniFi OS console* (the API lives under
   `/proxy/network/integration`), *self-hosted Network Application* (under `/integration`), or *detect
   automatically* (the first sync tries the UniFi OS path and then the other, and remembers the
   result). Adding a console needs a sign-in from the last ten minutes.
2. **Confirm the certificate.** UniFi consoles usually have a self-signed certificate, so GarnetOps
   cannot ask a certificate authority whether it is genuine. It reads the certificate the console
   presents (**without sending the key**) and shows its SHA-256 fingerprint. Compare it with the
   certificate details your browser shows for the console's address, or run on the console:

   ```sh
   openssl x509 -in /data/unifi-core/config/unifi-core.crt -noout -fingerprint -sha256
   ```

   Confirm it (again with a recent sign-in). GarnetOps then pins exactly that certificate: every
   request must present it, or the sync stops. The first sync starts at once.
3. If the certificate changes later (a renewal, a replaced console, or someone intercepting the
   connection), the sync **stops before any request is sent**, owners and admins are told once, and
   you see both certificates in **Settings → UniFi → Review the change**. Compare, then confirm. A
   certificate that is renewed often needs a new confirmation each time, so prefer the console's
   long-lived certificate for this connection.

A sync runs **every 15 minutes** and on request (**Sync now**). Private addresses are allowed
(consoles live in your network); loopback, link-local and cloud-metadata addresses are refused.

## 3. The Network devices tab

- One card per console: version, devices online, offline, firmware updates, sites, **clients as a
  number**, last sync, certificate state and, if you use it, the preview badge.
- The device table: name and model, site, address, status, firmware and uptime; more columns on wide
  screens. Filter by *Offline* or *Update available*, console, site, status or text (name, model, MAC,
  address, firmware). Sort by any column. Open a device for all facts.
- **Offline** is shown when the console calls a device offline (`OFFLINE`, `CONNECTION_INTERRUPTED`,
  `ISOLATED`). A device that is updating or waiting for adoption is not offline. GarnetOps counts how
  long a device has been in its state from when it first saw it; the console does not say.
- **Update available** is a maintenance hint taken from the console. **GarnetOps cannot match network
  firmware against vulnerability data** (the vulnerability scanner works on package inventories), so
  no device is ever called *vulnerable* here, and a device that is up to date is not "safe" either.

### Privacy: clients are a number

The console knows every phone and laptop on your network. GarnetOps asks for **one** entry of the
client list and reads only the **total**. No client name, MAC address or address is read into the
database, shown or logged. Devices (gateway, switches, access points) are stored with their name,
model, MAC address, IP address, state, firmware and uptime.

## 4. Notifications

Under **Account → Notifications** you choose, per person, whether to be told in the app and by email
(owners and admins; see [notifications.md](notifications.md)):

| Event | When |
| --- | --- |
| A UniFi certificate changed | Once per change; the sync stops until an admin confirms it |
| A UniFi device is offline | A device was offline in **two syncs in a row** (so a reboot or an update is not an alarm). One message per sync with the count and a name; not again until the device was online |
| A UniFi firmware update is available | Once per device and installed firmware version; one message per sync |

## 5. IPS and threat events (preview)

> **Preview.** The official API does not report blocked or detected threats. The console's *internal*
> API does, but Ubiquiti does not document or promise it. It can change with any UniFi update and the
> preview may stop working without notice. It is off by default and nothing else in GarnetOps depends
> on it.

What it shows: the time, the **source address**, whether the console **blocked** or only **detected**
the traffic, the signature and category (for example *ET SCAN … SSH brute force*), and the port that
was targeted. These events join the attack overview: the world map and **globe** (blocked ones as
dashed blue lines, legend *Blocked by UniFi*, next to the orange *Observed* lines), the countries,
networks and addresses tables, and the live list. Signatures are written by whoever attacks you: they
are shown as plain text and never sent to an AI model. **Not kept:** the packet or payload, the
destination address or host, the source port, user names.

### Create a view-only user

The preview logs in with a **separate local console user**, never with your owner or an administrator:

1. In the console, open **Admins & Users** and add a new **local** user (not a Ubiquiti account; no
   two-factor sign-in, a cookie login cannot do that). Use a neutral name such as `garnetops-view`.
2. Give it the role **View Only** for the Network application.
3. In **Settings → UniFi**, open **Set up the preview** for the console, enter the user name and
   password, the interval (30 to 600 seconds, 60 by default), tick the acknowledgement and switch it
   on (a recent sign-in is needed).

Names such as `admin`, `root`, `ubnt` or `owner` are refused.

**Rights beyond viewing block the preview.** At each login GarnetOps reads which rights the console
reports for the user: an owner or super administrator flag, and every role that is not recognisably
view-only (`View Only`, `Read Only`, `readonly`, `Viewer`). If there is any, the preview logs out
again at once and **reads nothing** (a critical badge, the list of rights in Settings → UniFi, an
audit entry, and a notification to owners and admins). A stolen password would not be limited to
reading, so an owner or admin has to decide:

- Preferably fix it on the console: give the user only the view-only role. GarnetOps looks again
  every ten minutes and continues by itself when the list is empty.
- Or **Review rights** in Settings → UniFi, compare the list and acknowledge exactly that list
  (a recent sign-in is needed; the acknowledgement is audited). The preview then starts at once.

The acknowledgement counts only for that exact list. If the console later reports other rights
(more, fewer or different ones), it is void, the preview stops again and the admins are told. Changing
the user or the password, or pointing the connection at another console, starts from scratch. This
check is best effort: it cannot see rights that the console does not report in the login answer, so
always create the user with the view-only role.

### How it works

Every poll is *login, read, logout*. The cookie and CSRF token stay in the memory of the worker for
those seconds and are never stored. The only POST requests GarnetOps can send are the console's login
and logout; the only read is the IPS event list of a site. The password is sealed in the vault and
opened by the worker only. The certificate must be confirmed first, and a changed certificate blocks
the preview before the password is sent.

Events are kept for the retention period of the attack overview (90 days by default; **Settings →
Attack overview**), at most 20,000 per console. **Delete stored addresses now** deletes them too.
The Attacks page shows a status line: *UniFi IPS preview: live, last event 12 s ago*, *waiting for the
console* (with the reason) or *paused*. UniFi OS may limit logins; GarnetOps then waits longer.

## Firewall

Allow the GarnetOps **worker** to reach the console: TCP 443 (UniFi OS) or 8443 (Network Application,
unless you changed it). Nothing else needs to reach the console, and GarnetOps opens no inbound port
for UniFi. In the Compose stack the worker's `egress` network should allow only the console's address
and port.

## What GarnetOps does not do

- Use the Ubiquiti cloud or any account of yours at Ubiquiti.
- Change, restart, adopt, upgrade or rename anything on the console; read the client list beyond its
  number; read Wi-Fi passphrases, VPN, firewall or user settings.
- Call a device vulnerable, or fetch firmware release notes.
- Run on a console older than the official local API (Network application 9.0).

## Not tested against a real console

The endpoints and field names are assumptions based on Ubiquiti's published reference and on public
knowledge of the internal API, tested against a local HTTPS server that replays synthetic answers.
They can differ per version; see ADR 0022 for the exact list. If something does not match on your
console, the sync shows a short message ("unexpected format", "does not answer like the UniFi Network
API") and keeps the last good data.
