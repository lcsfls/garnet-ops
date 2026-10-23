/**
 * External exposure (ADR 0023): what GarnetOps looks at from the outside, the rules that turn what it saw into findings, the
 * fixed list of ports of the light active stage, and the proof of control that stage needs. Pure logic shared by the API, the
 * worker and the web app: this file has no Node-only imports (see exposure-assets.ts for those).
 *
 * Everything a remote system sends (DNS records, certificates, headers, banners) is hostile text. It is cut to a length,
 * stripped of control and bidirectional characters, stored as text and rendered as text. Nothing here interprets it as
 * markup, a link or an instruction.
 */

/* -------------------------------------------------------------------------- */
/* Limits                                                                      */
/* -------------------------------------------------------------------------- */

/** Assets per organisation. */
export const MAX_ASSETS = 200;
/** Addresses of one name that are looked at (the first ones of the resolver's answer). */
export const MAX_ADDRESSES_PER_ASSET = 4;
/** The body of the one page that is read is cut here and never stored. */
export const MAX_HTTP_BODY_BYTES = 64 * 1024;
/** Redirects that are followed, and only inside the same site or to a verified asset. */
export const MAX_REDIRECTS = 3;
/** Findings and snapshots keep this many characters of any one remote string. */
export const MAX_REMOTE_TEXT = 300;
/** Runs kept per asset and stage, newest first. */
export const RUNS_KEPT = 60;

/** Stage 2: how fast and how long a target is touched. These are enforced in code, not only documented. */
export const ACTIVE_LIMITS = {
  /** Connection attempts that are in flight at the same time, per target. */
  concurrency: 4,
  /** The least time between the start of two attempts at one target. */
  gapMs: 200,
  connectTimeoutMs: 3000,
  /** How long a banner is waited for, and how much of it is kept. */
  bannerReadMs: 2000,
  bannerBytes: 512,
  /** A target is scanned at most once in this time, whoever asks. */
  minIntervalHours: 24,
} as const;

/** The schedules of stage 2. */
export const ACTIVE_SCHEDULES = ["daily", "weekly"] as const;
export type ActiveSchedule = (typeof ACTIVE_SCHEDULES)[number];
export const SCHEDULE_HOURS: Record<ActiveSchedule, number> = { daily: 24, weekly: 24 * 7 };

/** Stage 1 runs this often, and the proof of control is checked this often. */
export const PASSIVE_INTERVAL_HOURS = 24;
export const VERIFY_INTERVAL_HOURS = 24;
/** Stage 2 needs a proof that was confirmed within this time. */
export const VERIFY_FRESH_HOURS = 48;

/* -------------------------------------------------------------------------- */
/* Vocabulary                                                                  */
/* -------------------------------------------------------------------------- */

export const ASSET_KINDS = ["domain", "ip"] as const;
export type AssetKind = (typeof ASSET_KINDS)[number];

export const VERIFY_STATES = ["unverified", "verified", "lost"] as const;
export type VerifyState = (typeof VERIFY_STATES)[number];
export const VERIFY_METHODS = ["dns", "http"] as const;
export type VerifyMethod = (typeof VERIFY_METHODS)[number];

/** Severities of exposure findings. A subset of the platform's severities: a finding is at least low. */
export const EXPOSURE_SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type ExposureSeverity = (typeof EXPOSURE_SEVERITIES)[number];
export const SEVERITY_RANK: Record<ExposureSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export const RUN_STAGES = ["passive", "active"] as const;
export type RunStage = (typeof RUN_STAGES)[number];

/** Codes stored on runs and on the verification check. The web app turns each into a sentence. */
export const EXPOSURE_ERRORS = [
  "assetRemoved",
  "notVerified",
  "notAcknowledged",
  "stageOff",
  "tooSoon",
  "addressRefused",
  "unresolvable",
  "timeout",
  "unexpected",
  "dnsRecordMissing",
  "dnsNoMatch",
  "dnsFailed",
  "fileUnreachable",
  "fileNotFound",
  "fileNoMatch",
  "fileRedirected",
  "fileTooLarge",
  "tlsFailed",
] as const;
export type ExposureErrorCode = (typeof EXPOSURE_ERRORS)[number];
export const isExposureError = (value: unknown): value is ExposureErrorCode =>
  typeof value === "string" && (EXPOSURE_ERRORS as readonly string[]).includes(value);

/** The wording the acknowledgement of stage 2 has; its identifier is stored in the audit log with the user and the asset. */
export const STAGE2_ACKNOWLEDGEMENT_ID = "exposure-stage2-v1";

/* -------------------------------------------------------------------------- */
/* Certificate Transparency (opt-in)                                           */
/* -------------------------------------------------------------------------- */

/**
 * The one Certificate Transparency search service the provider interface knows. Using it sends the domain name of a verified asset to
 * this service, which is data leaving the network: it is off until an owner or admin switches it on (ADR 0023). The URL is shown in
 * the interface exactly as it is requested.
 */
export const CT_PROVIDER = {
  id: "crtsh",
  name: "crt.sh",
  operator: "Sectigo",
  host: "crt.sh",
  /** `{domain}` is replaced by the domain of a verified asset. */
  urlTemplate: "https://crt.sh/?q=%25.{domain}&output=json&exclude=expired",
} as const;

/** The path and query of a search for the subdomains of `domain`. */
export const ctPath = (domain: string): string =>
  `/?q=%25.${encodeURIComponent(domain)}&output=json&exclude=expired`;

export const CT_LIMITS = {
  /** Queries per organisation and day. */
  dailyBudget: 100,
  /** The least time between two queries of one organisation. */
  minGapMs: 10_000,
  /** An asset is looked up at most this often. */
  assetIntervalHours: 24,
  maxBytes: 4 * 1024 * 1024,
  timeoutMs: 30_000,
  /** Names kept per answer. */
  maxNames: 500,
} as const;

/* -------------------------------------------------------------------------- */
/* Remote text                                                                 */
/* -------------------------------------------------------------------------- */

function isBad(code: number, keepNewline: boolean): boolean {
  if (keepNewline && code === 0x0a) return false;
  return (
    code < 0x20 ||
    (code >= 0x7f && code <= 0x9f) ||
    code === 0x2028 ||
    code === 0x2029 ||
    code === 0x200b ||
    code === 0xfeff ||
    (code >= 0x200e && code <= 0x200f) ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2066 && code <= 0x2069)
  );
}

/**
 * Plain text from something a remote system sent: control and bidirectional characters become spaces (a line break stays one
 * when `multiline` is set, at most six lines), runs of blanks collapse, the result is cut at `max` characters. Never throws.
 */
export function plainText(input: string, max = MAX_REMOTE_TEXT, multiline = false): string {
  let out = "";
  for (const char of input) {
    const code = char.codePointAt(0) ?? 0;
    if (code === 0x0d) continue;
    out += isBad(code, multiline) ? " " : char;
  }
  if (multiline) {
    const lines = out
      .split("\n")
      .map((line) => line.replace(/[ \t]+/g, " ").trim())
      .filter((line) => line.length > 0)
      .slice(0, 6);
    out = lines.join("\n");
  } else {
    out = out.replace(/\s+/g, " ").trim();
  }
  return [...out].slice(0, max).join("");
}

/**
 * The text of a banner a service sent first: at most `ACTIVE_LIMITS.bannerBytes` bytes are looked at, decoded leniently, then
 * cleaned as {@link plainText} (line breaks kept). Binary garbage becomes a short string of blanks and replacement marks,
 * which is why an all-garbage banner reads as empty (null).
 */
export function sanitizeBanner(bytes: Uint8Array): string | null {
  const slice = bytes.subarray(0, ACTIVE_LIMITS.bannerBytes);
  const text = new TextDecoder("utf-8", { fatal: false }).decode(slice);
  const clean = plainText(text, ACTIVE_LIMITS.bannerBytes, true);
  const printable = [...clean].filter((c) => c !== "�" && c !== " " && c !== "\n").length;
  return printable === 0 ? null : clean;
}

/* -------------------------------------------------------------------------- */
/* Sites                                                                       */
/* -------------------------------------------------------------------------- */

/** Second-level labels under a two-letter country code that are registrable domains themselves (co.uk, com.au). */
const SECOND_LEVEL = new Set([
  "co",
  "com",
  "org",
  "net",
  "gov",
  "edu",
  "ac",
  "or",
  "ne",
  "go",
  "ltd",
  "plc",
  "sch",
  "me",
]);

/**
 * The part of a host name an organisation can register: the last two labels, or three under a country code with a
 * registry level such as co.uk. An approximation without the public suffix list (which this product does not bundle); it errs on
 * the side of treating a name as a separate site.
 */
export function registrableDomain(host: string): string {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".");
  if (labels.length <= 2) return labels.join(".");
  const tld = labels[labels.length - 1] as string;
  const second = labels[labels.length - 2] as string;
  if (tld.length === 2 && SECOND_LEVEL.has(second)) return labels.slice(-3).join(".");
  return labels.slice(-2).join(".");
}

export const isSameSite = (a: string, b: string): boolean => registrableDomain(a) === registrableDomain(b);

/**
 * Whether a redirect from one host to another may be followed: the same registrable domain, or a host that is a verified
 * asset of the organisation. Everything else is recorded and not followed.
 */
export function mayFollowRedirect(from: string, to: string, verifiedHosts: ReadonlySet<string>): boolean {
  const source = from.toLowerCase().replace(/^\[|\]$/g, "");
  const target = to.toLowerCase().replace(/^\[|\]$/g, "");
  if (verifiedHosts.has(target)) return true;
  // An address has no registrable domain: it may only be redirected to itself.
  if (looksLikeAddress(source) || looksLikeAddress(target)) return source === target;
  return isSameSite(source, target);
}

const looksLikeAddress = (host: string): boolean => /^[\d.]+$/.test(host) || host.includes(":");

/* -------------------------------------------------------------------------- */
/* Verification                                                                */
/* -------------------------------------------------------------------------- */

export const CHALLENGE_LABEL = "_garnetops-challenge";
export const VERIFY_PREFIX = "garnetops-verify=";
export const VERIFY_FILE_PATH = "/.well-known/garnetops-verify.txt";
/** The proof file is read up to this size; a larger answer is refused. */
export const MAX_VERIFY_FILE_BYTES = 1024;
/** The least a token has: 256 bits as 43 base64url characters. */
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export const isVerifyToken = (value: unknown): value is string =>
  typeof value === "string" && TOKEN_PATTERN.test(value);

/** The TXT record value an owner publishes. */
export const verifyRecordValue = (token: string): string => `${VERIFY_PREFIX}${token}`;
/** The name the TXT record lives at. */
export const challengeName = (domain: string): string => `${CHALLENGE_LABEL}.${domain}`;
/** Where the proof file is served for a host or an address (an IPv6 address in brackets). */
export function verifyFileUrl(value: string, scheme: "https" | "http" = "https"): string {
  const host = value.includes(":") ? `[${value}]` : value;
  return `${scheme}://${host}${VERIFY_FILE_PATH}`;
}

/**
 * Whether a TXT answer (a list of records, each a list of character strings) contains the proof: one record whose strings,
 * joined, equal `garnetops-verify=<token>` (surrounding blanks ignored). The comparison is exact: a longer or different token
 * is no proof. The token is public by design (it is published in DNS), so no constant-time comparison is needed; what makes
 * it proof is that it is unguessable and belongs to one organisation and one asset.
 */
export function txtMatchesToken(records: readonly (readonly string[])[], token: string): boolean {
  if (!isVerifyToken(token)) return false;
  const wanted = verifyRecordValue(token);
  return records.some((strings) => strings.join("").trim() === wanted);
}

/** Whether the body of the proof file holds the token on a line of its own, bare or as `garnetops-verify=<token>`. */
export function fileMatchesToken(body: string, token: string): boolean {
  if (!isVerifyToken(token) || body.length > MAX_VERIFY_FILE_BYTES) return false;
  const wanted = verifyRecordValue(token);
  return body.split(/\r?\n/).some((line) => {
    const text = line.trim();
    return text === token || text === wanted;
  });
}

export interface VerifiableAsset {
  id: string;
  kind: AssetKind;
  value: string;
  verifyState: VerifyState;
  includeSubdomains: boolean;
}

/**
 * Whether an asset counts as verified: its own proof, or the proof of a verified parent domain of the organisation that
 * has "include subdomains" switched on. An address is never covered by a domain. The result names the covering asset.
 */
export function effectiveVerification(
  asset: VerifiableAsset,
  all: readonly VerifiableAsset[],
): { verified: boolean; via: "self" | "parent" | null; parentId: string | null } {
  if (asset.verifyState === "verified") return { verified: true, via: "self", parentId: null };
  if (asset.kind !== "domain") return { verified: false, via: null, parentId: null };
  const parent = all.find(
    (other) =>
      other.id !== asset.id &&
      other.kind === "domain" &&
      other.verifyState === "verified" &&
      other.includeSubdomains &&
      asset.value.endsWith(`.${other.value}`),
  );
  return parent
    ? { verified: true, via: "parent", parentId: parent.id }
    : { verified: false, via: null, parentId: null };
}

/* -------------------------------------------------------------------------- */
/* Ports of stage 2                                                            */
/* -------------------------------------------------------------------------- */

export const PORT_CATEGORIES = [
  "cleartext",
  "remoteAccess",
  "fileSharing",
  "database",
  "managementApi",
  "development",
  "expected",
] as const;
export type PortCategory = (typeof PORT_CATEGORIES)[number];

export interface PortSpec {
  port: number;
  /** A short id; the web app has a name for it (`exposure.service.<id>`). */
  service: string;
  category: PortCategory;
  /** The service speaks first (SSH, SMTP, FTP, IMAP, POP3): the first bytes are read, nothing is sent. */
  banner: boolean;
  /** The service starts with TLS: the handshake is made, which is the only thing ever sent to a port. */
  tls: boolean;
  /** Severity of "this is reachable from the internet"; null is a port that is normal to see open and no finding. */
  severity: ExposureSeverity | null;
}

/**
 * The fixed list of stage 2 and what each port means. An installation cannot add to it (the code only knows this list) and
 * the documentation (`docs/exposure.md`) shows it. The severity says how unusual it is to see the service open to the internet,
 * not that it is vulnerable: GarnetOps sends nothing to the service and so cannot tell.
 */
export const EXPOSURE_PORTS: readonly PortSpec[] = [
  { port: 21, service: "ftp", category: "cleartext", banner: true, tls: false, severity: "medium" },
  { port: 22, service: "ssh", category: "expected", banner: true, tls: false, severity: null },
  { port: 23, service: "telnet", category: "remoteAccess", banner: false, tls: false, severity: "high" },
  { port: 25, service: "smtp", category: "expected", banner: true, tls: false, severity: null },
  { port: 53, service: "dns", category: "expected", banner: false, tls: false, severity: null },
  { port: 80, service: "http", category: "expected", banner: false, tls: false, severity: null },
  { port: 110, service: "pop3", category: "cleartext", banner: true, tls: false, severity: "low" },
  { port: 143, service: "imap", category: "cleartext", banner: true, tls: false, severity: "low" },
  { port: 443, service: "https", category: "expected", banner: false, tls: true, severity: null },
  { port: 445, service: "smb", category: "fileSharing", banner: false, tls: false, severity: "high" },
  { port: 465, service: "smtps", category: "expected", banner: false, tls: true, severity: null },
  { port: 587, service: "submission", category: "expected", banner: true, tls: false, severity: null },
  { port: 993, service: "imaps", category: "expected", banner: false, tls: true, severity: null },
  { port: 995, service: "pop3s", category: "expected", banner: false, tls: true, severity: null },
  { port: 1433, service: "mssql", category: "database", banner: false, tls: false, severity: "high" },
  { port: 1521, service: "oracle", category: "database", banner: false, tls: false, severity: "high" },
  {
    port: 2375,
    service: "docker",
    category: "managementApi",
    banner: false,
    tls: false,
    severity: "critical",
  },
  {
    port: 2376,
    service: "dockerTls",
    category: "managementApi",
    banner: false,
    tls: true,
    severity: "medium",
  },
  { port: 3000, service: "devServer", category: "development", banner: false, tls: false, severity: "low" },
  { port: 3306, service: "mysql", category: "database", banner: false, tls: false, severity: "high" },
  { port: 3389, service: "rdp", category: "remoteAccess", banner: false, tls: false, severity: "high" },
  { port: 5432, service: "postgres", category: "database", banner: false, tls: false, severity: "high" },
  { port: 5900, service: "vnc", category: "remoteAccess", banner: false, tls: false, severity: "high" },
  { port: 6379, service: "redis", category: "database", banner: false, tls: false, severity: "high" },
  { port: 8000, service: "httpAlt", category: "development", banner: false, tls: false, severity: "low" },
  { port: 8080, service: "httpProxy", category: "development", banner: false, tls: false, severity: "low" },
  { port: 8443, service: "httpsAlt", category: "expected", banner: false, tls: true, severity: null },
  { port: 9200, service: "elasticsearch", category: "database", banner: false, tls: false, severity: "high" },
  { port: 11211, service: "memcached", category: "database", banner: false, tls: false, severity: "high" },
  { port: 27017, service: "mongodb", category: "database", banner: false, tls: false, severity: "high" },
];

export const portSpec = (port: number): PortSpec | undefined => EXPOSURE_PORTS.find((p) => p.port === port);

/** A service this severe or worse also sends a notification (`exposure.risky_service`). */
export const isRiskyService = (severity: ExposureSeverity | null): boolean =>
  severity === "high" || severity === "critical";

/* -------------------------------------------------------------------------- */
/* Snapshots: what a run saw                                                   */
/* -------------------------------------------------------------------------- */

export interface CertInfo {
  subject: string;
  issuer: string;
  /** Subject alternative names (DNS names and addresses), at most 20. */
  sans: string[];
  validFrom: string;
  validTo: string;
  /** SHA-256 of the DER certificate, upper-case hex pairs separated by colons. */
  fingerprint: string;
  keyType: string | null;
  keyBits: number | null;
  selfSigned: boolean;
}

export interface TlsSnapshot {
  address: string;
  port: number;
  /** False when no handshake was made (nothing listening, a timeout, a service that does not speak TLS). */
  ok: boolean;
  /** A short reason for `ok: false`. */
  error: "refused" | "timeout" | "handshake" | null;
  protocol: string | null;
  cipher: string | null;
  /** Whether the chain verifies against the system's certificate store and the name matches; null when not judged. */
  trusted: boolean | null;
  /** The verifier's reason (an OpenSSL code such as CERT_HAS_EXPIRED), cleaned. */
  trustError: string | null;
  /** Whether a name was checked and matched; null for an address or when nothing was presented. */
  nameMatches: boolean | null;
  cert: CertInfo | null;
  chainLength: number;
  /** Whether TLS 1.0 and TLS 1.1 were accepted; null when the probe did not ask. */
  legacy: { tls10: boolean | null; tls11: boolean | null } | null;
}

export interface HttpSnapshot {
  address: string | null;
  url: string;
  finalUrl: string | null;
  status: number | null;
  redirects: { to: string; status: number; followed: boolean }[];
  /** The captured response headers, cleaned; only the names in {@link CAPTURED_HEADERS}. */
  headers: Record<string, string>;
  error: "refused" | "timeout" | "tls" | "address" | "protocol" | "tooLarge" | null;
}

export interface PlainHttpSnapshot {
  address: string | null;
  status: number | null;
  location: string | null;
  /** The answer redirects to an https address. null when it did not answer. */
  redirectsToHttps: boolean | null;
  error: "refused" | "timeout" | "protocol" | null;
}

export interface DnsSnapshot {
  /** Record types whose lookup failed (a timeout, SERVFAIL): the rules that need them stay silent instead of guessing. */
  failed: ("a" | "aaaa" | "txt" | "dmarc" | "caa")[];
  a: string[];
  aaaa: string[];
  cname: string[];
  mx: { priority: number; exchange: string }[];
  ns: string[];
  caa: { critical: boolean; tag: string; value: string }[];
  /** Whether a CAA record was found at the name or any parent up to the registrable domain. */
  caaFound: boolean;
  /** The SPF record (cleaned) and how many there are; DMARC likewise. */
  spf: { records: number; policy: SpfPolicy; record: string | null };
  dmarc: { found: boolean; policy: DmarcPolicy | null; record: string | null };
  /** The resolver API does not report DNSSEC validation: always "unknown" (the web app says so). */
  dnssec: "unknown";
}

export interface GeoEntry {
  address: string;
  country: string | null;
  asn: number | null;
  org: string | null;
}

export interface PassiveSnapshot {
  version: 1;
  takenAt: string;
  kind: AssetKind;
  name: string;
  /** The public addresses that were looked at (at most {@link MAX_ADDRESSES_PER_ASSET}). */
  addresses: string[];
  /** Addresses the name resolved to that are not public; nothing was connected to them, or to any other address of the name. */
  nonPublic: string[];
  dns: DnsSnapshot | null;
  /** Reverse names of the addresses of an address asset (display only), at most five. */
  ptr: string[];
  tls: TlsSnapshot[];
  http: HttpSnapshot | null;
  plain: PlainHttpSnapshot | null;
  geo: GeoEntry[];
  /** Whether the name has no address at all. */
  resolves: boolean;
  /** Whether port 443 accepted a connection on any looked-at address. */
  httpsOpen: boolean;
}

export interface PortResult {
  address: string;
  port: number;
  service: string;
  category: PortCategory;
  /** How unusual it is to see this service open to the internet (the table's severity), or null. */
  severity: ExposureSeverity | null;
  banner: string | null;
  tls: TlsSnapshot | null;
}

export interface ActiveSnapshot {
  version: 1;
  takenAt: string;
  addresses: string[];
  /** Open ports only. */
  open: PortResult[];
  checked: number;
  closed: number;
  noAnswer: number;
  /** A code when the run stopped early (the proof of control disappeared, ...). */
  stopped: ExposureErrorCode | null;
}

/** Response headers that are kept, in this order. Everything else a server sends is dropped. */
export const CAPTURED_HEADERS = [
  "server",
  "x-powered-by",
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
] as const;

/* -------------------------------------------------------------------------- */
/* DNS policies: SPF and DMARC                                                 */
/* -------------------------------------------------------------------------- */

export type SpfPolicy = "fail" | "softfail" | "neutral" | "pass" | "redirect" | "none";
export type DmarcPolicy = "none" | "quarantine" | "reject";

/** The SPF records among a name's TXT records (a record starts with `v=spf1`), joined from their strings. */
export function spfRecords(txt: readonly (readonly string[])[]): string[] {
  return txt.map((strings) => strings.join("").trim()).filter((record) => /^v=spf1(\s|$)/i.test(record));
}

/** What the `all` mechanism of an SPF record says: `-all` fail, `~all` softfail, `?all` neutral, `+all` or `all` pass. */
export function spfPolicy(record: string | undefined): SpfPolicy {
  if (!record) return "none";
  const terms = record.toLowerCase().split(/\s+/);
  if (terms.some((t) => t.startsWith("redirect="))) return "redirect";
  const all = terms.find((t) => /^[+\-~?]?all$/.test(t));
  if (!all) return "none";
  if (all.startsWith("-")) return "fail";
  if (all.startsWith("~")) return "softfail";
  if (all.startsWith("?")) return "neutral";
  return "pass";
}

/** The DMARC policy (`p=`) of a `_dmarc` TXT answer, or null if there is no valid DMARC record. */
export function dmarcPolicy(txt: readonly (readonly string[])[]): DmarcPolicy | null {
  for (const strings of txt) {
    const record = strings.join("").trim();
    if (!/^v=DMARC1\s*(;|$)/i.test(record)) continue;
    const tags = new Map<string, string>();
    for (const part of record.split(";")) {
      const eq = part.indexOf("=");
      if (eq < 1) continue;
      const name = part.slice(0, eq).trim().toLowerCase();
      if (!tags.has(name))
        tags.set(
          name,
          part
            .slice(eq + 1)
            .trim()
            .toLowerCase(),
        );
    }
    const policy = tags.get("p");
    if (policy === "none" || policy === "quarantine" || policy === "reject") return policy;
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/* HTTP header rules                                                           */
/* -------------------------------------------------------------------------- */

/** `max-age`, `includeSubDomains` and `preload` of a Strict-Transport-Security header; null when it has no max-age. */
export function parseHsts(
  value: string | undefined,
): { maxAge: number; includeSubDomains: boolean; preload: boolean } | null {
  if (!value) return null;
  let maxAge: number | null = null;
  let includeSubDomains = false;
  let preload = false;
  for (const part of value.split(";")) {
    const directive = part.trim().toLowerCase();
    const age = /^max-age\s*=\s*"?(\d{1,12})"?$/.exec(directive);
    if (age) maxAge = Number(age[1]);
    else if (directive === "includesubdomains") includeSubDomains = true;
    else if (directive === "preload") preload = true;
  }
  return maxAge === null ? null : { maxAge, includeSubDomains, preload };
}

/** HSTS with a max-age under 180 days is called weak. */
export const HSTS_WEAK_BELOW_SECONDS = 180 * 86_400;

const hasFrameAncestors = (csp: string | undefined) => /(^|;)\s*frame-ancestors\s/i.test(csp ?? "");
/** A banner that names a version number (`nginx/1.22.1`, `Apache/2.4.57 (Debian)`, `PHP/8.2.7`). */
export const bannerHasVersion = (banner: string | undefined): boolean =>
  /[A-Za-z][\w.-]*[/ _-]v?\d+\.\d+/.test(banner ?? "");

/* -------------------------------------------------------------------------- */
/* Findings                                                                    */
/* -------------------------------------------------------------------------- */

/** Every rule id a finding can have. The web app has a title and a sentence for each (`exposure.rules.<id>`). */
export const EXPOSURE_RULES = [
  "tlsExpired",
  "tlsExpiring",
  "tlsUntrusted",
  "tlsNameMismatch",
  "tlsWeakKey",
  "tlsLegacyProtocol",
  "httpHstsMissing",
  "httpHstsWeak",
  "httpCspMissing",
  "httpNosniffMissing",
  "httpFramingMissing",
  "httpReferrerPolicyMissing",
  "httpPermissionsPolicyMissing",
  "httpBannerVersion",
  "httpNoRedirectToHttps",
  "httpNoHttps",
  "dnsNoSpf",
  "dnsSpfMultiple",
  "dnsSpfPermissive",
  "dnsNoDmarc",
  "dnsDmarcNone",
  "dnsNoCaa",
  "dnsDanglingCname",
  "dnsNonPublicAddress",
  "portExposed",
] as const;
export type ExposureRule = (typeof EXPOSURE_RULES)[number];

export interface FindingDraft {
  /** One of {@link EXPOSURE_RULES}. */
  rule: ExposureRule;
  /** Distinguishes several findings of one rule on an asset (a header name, a port); empty if there is only one. */
  subject: string;
  severity: ExposureSeverity;
  stage: RunStage;
  /** Short facts the sentence uses: numbers and cleaned text. Never a secret, never raw output. */
  params: Record<string, string | number>;
}

const finding = (
  rule: ExposureRule,
  severity: ExposureSeverity,
  stage: RunStage,
  subject = "",
  params: Record<string, string | number> = {},
): FindingDraft => ({ rule, subject, severity, stage, params });

/** Whole days from `now` to the end of a certificate's validity; negative once it has expired. */
export function daysToExpiry(validTo: string, now: Date): number {
  return Math.floor((new Date(validTo).getTime() - now.getTime()) / 86_400_000);
}

/** The expiry warning step a number of days falls in: 30, 14, 7, or 0 for expired. null while more than 30 days are left. */
export type ExpiryLevel = 30 | 14 | 7 | 0;
export function expiryLevel(days: number): ExpiryLevel | null {
  if (days < 0) return 0;
  if (days <= 7) return 7;
  if (days <= 14) return 14;
  if (days <= 30) return 30;
  return null;
}

/**
 * Whether a warning for `level` is due, given the level that was already announced (null: none yet). A warning is sent when the
 * certificate reaches a more urgent level than the last one told; a renewed certificate (level null) resets it.
 */
export function expiryWarningDue(level: ExpiryLevel | null, announced: number | null): boolean {
  if (level === null) return false;
  return announced === null || level < announced;
}

/** Findings of one TLS handshake. `subject` is the port, so a second TLS port does not overwrite the first. */
export function tlsFindings(tls: TlsSnapshot, now: Date, stage: RunStage): FindingDraft[] {
  const out: FindingDraft[] = [];
  const subject = String(tls.port);
  const base = { port: tls.port, address: tls.address };
  if (tls.ok && tls.cert) {
    const days = daysToExpiry(tls.cert.validTo, now);
    if (days < 0) out.push(finding("tlsExpired", "high", stage, subject, { ...base, days: -days }));
    else if (days <= 30) {
      const severity: ExposureSeverity = days <= 7 ? "high" : days <= 14 ? "medium" : "low";
      out.push(finding("tlsExpiring", severity, stage, subject, { ...base, days }));
    }
    if (tls.trusted === false && days >= 0) {
      const mismatch = tls.nameMatches === false;
      out.push(
        finding(mismatch ? "tlsNameMismatch" : "tlsUntrusted", "medium", stage, subject, {
          ...base,
          reason: tls.trustError ?? "",
        }),
      );
    }
    if (tls.cert.keyType === "rsa" && tls.cert.keyBits !== null && tls.cert.keyBits < 2048) {
      out.push(finding("tlsWeakKey", "medium", stage, subject, { ...base, bits: tls.cert.keyBits }));
    }
  }
  if (tls.legacy?.tls10 || tls.legacy?.tls11) {
    const versions = [tls.legacy.tls10 ? "TLS 1.0" : null, tls.legacy.tls11 ? "TLS 1.1" : null]
      .filter((v) => v !== null)
      .join(", ");
    out.push(finding("tlsLegacyProtocol", "medium", stage, subject, { ...base, versions }));
  }
  return out;
}

/** Findings of the HTTP answers, the DNS records and TLS of an asset. See ADR 0023 for the rules and their severities. */
export function evaluatePassive(snapshot: PassiveSnapshot, now: Date): FindingDraft[] {
  const out: FindingDraft[] = [];
  const stage: RunStage = "passive";

  // TLS: the worst certificate wins per rule, one finding per rule and port.
  const byKey = new Map<string, FindingDraft>();
  for (const tls of snapshot.tls) {
    for (const f of tlsFindings(tls, now, stage)) {
      const key = `${f.rule}|${f.subject}`;
      const known = byKey.get(key);
      if (!known || SEVERITY_RANK[f.severity] > SEVERITY_RANK[known.severity]) byKey.set(key, f);
    }
  }
  out.push(...byKey.values());

  const http = snapshot.http;
  if (http && http.status !== null) {
    const h = http.headers;
    const https = (http.finalUrl ?? http.url).startsWith("https://");
    if (https) {
      const hsts = parseHsts(h["strict-transport-security"]);
      if (!hsts) out.push(finding("httpHstsMissing", "low", stage));
      else if (hsts.maxAge < HSTS_WEAK_BELOW_SECONDS) {
        out.push(finding("httpHstsWeak", "low", stage, "", { seconds: hsts.maxAge }));
      }
    }
    if (!h["content-security-policy"]) out.push(finding("httpCspMissing", "low", stage));
    if ((h["x-content-type-options"] ?? "").toLowerCase() !== "nosniff") {
      out.push(finding("httpNosniffMissing", "low", stage));
    }
    if (!hasFrameAncestors(h["content-security-policy"]) && !h["x-frame-options"]) {
      out.push(finding("httpFramingMissing", "low", stage));
    }
    if (!h["referrer-policy"]) out.push(finding("httpReferrerPolicyMissing", "low", stage));
    if (!h["permissions-policy"]) out.push(finding("httpPermissionsPolicyMissing", "low", stage));
    for (const name of ["server", "x-powered-by"] as const) {
      const banner = h[name];
      if (bannerHasVersion(banner)) {
        out.push(finding("httpBannerVersion", "low", stage, name, { header: name, banner: banner ?? "" }));
      }
    }
  }
  const plain = snapshot.plain;
  if (plain && plain.status !== null && plain.redirectsToHttps === false && snapshot.httpsOpen) {
    out.push(finding("httpNoRedirectToHttps", "medium", stage, "", { status: plain.status }));
  }
  if (plain && plain.status !== null && !snapshot.httpsOpen && snapshot.resolves) {
    out.push(finding("httpNoHttps", "medium", stage));
  }

  const dns = snapshot.dns;
  if (snapshot.nonPublic.length > 0) {
    out.push(
      finding("dnsNonPublicAddress", "low", stage, "", {
        addresses: snapshot.nonPublic.slice(0, 4).join(", "),
      }),
    );
  }
  if (dns) {
    const hasMail = dns.mx.length > 0;
    if (dns.cname.length > 0 && !snapshot.resolves) {
      out.push(finding("dnsDanglingCname", "medium", stage, "", { target: dns.cname[0] ?? "" }));
    }
    const textKnown = !dns.failed.includes("txt");
    if (textKnown && dns.spf.records === 0) out.push(finding("dnsNoSpf", hasMail ? "medium" : "low", stage));
    else if (textKnown) {
      if (dns.spf.records > 1)
        out.push(finding("dnsSpfMultiple", "medium", stage, "", { count: dns.spf.records }));
      if (dns.spf.policy === "pass" || dns.spf.policy === "neutral") {
        out.push(finding("dnsSpfPermissive", "medium", stage, "", { policy: dns.spf.policy }));
      }
    }
    if (!dns.failed.includes("dmarc")) {
      if (!dns.dmarc.found) out.push(finding("dnsNoDmarc", hasMail ? "medium" : "low", stage));
      else if (dns.dmarc.policy === "none") out.push(finding("dnsDmarcNone", "low", stage));
    }
    if (!dns.failed.includes("caa") && !dns.caaFound) out.push(finding("dnsNoCaa", "low", stage));
  }
  return out;
}

const TLS_RULES: ExposureRule[] = [
  "tlsExpired",
  "tlsExpiring",
  "tlsUntrusted",
  "tlsNameMismatch",
  "tlsWeakKey",
  "tlsLegacyProtocol",
];
const HTTP_RULES: ExposureRule[] = [
  "httpHstsMissing",
  "httpHstsWeak",
  "httpCspMissing",
  "httpNosniffMissing",
  "httpFramingMissing",
  "httpReferrerPolicyMissing",
  "httpPermissionsPolicyMissing",
  "httpBannerVersion",
];

/**
 * The rules a stage 1 snapshot could not judge, because a lookup failed or a server did not answer in time. Findings of these rules
 * are left as they are (neither opened nor resolved): "we could not look" must not read as "fixed".
 */
export function unjudgedRules(s: PassiveSnapshot): ExposureRule[] {
  const out: ExposureRule[] = [];
  const dns = s.dns;
  if (dns?.failed.includes("txt")) out.push("dnsNoSpf", "dnsSpfMultiple", "dnsSpfPermissive");
  if (dns?.failed.includes("dmarc")) out.push("dnsNoDmarc", "dnsDmarcNone");
  if (dns?.failed.includes("caa")) out.push("dnsNoCaa");
  const lookupFailed = dns?.failed.some((f) => f === "a" || f === "aaaa") ?? false;
  if (lookupFailed && s.addresses.length === 0) {
    out.push(
      "dnsDanglingCname",
      "dnsNonPublicAddress",
      "httpNoHttps",
      "httpNoRedirectToHttps",
      ...TLS_RULES,
      ...HTTP_RULES,
    );
    return out;
  }
  if (s.addresses.length > 0) {
    if (s.tls.length > 0 && s.tls.every((t) => !t.ok && t.error === "timeout")) out.push(...TLS_RULES);
    if (s.httpsOpen && (!s.http || (s.http.status === null && s.http.error !== null)))
      out.push(...HTTP_RULES);
    if (!s.plain || s.plain.error === "timeout") out.push("httpNoHttps", "httpNoRedirectToHttps");
  }
  return [...new Set(out)];
}

/** Findings of an active run: every open port the table calls unusual, and the TLS rules for the TLS ports. */
export function evaluateActive(snapshot: ActiveSnapshot, now: Date): FindingDraft[] {
  const out: FindingDraft[] = [];
  const stage: RunStage = "active";
  const byPort = new Map<number, { result: PortResult; addresses: string[] }>();
  for (const result of snapshot.open) {
    if (result.severity) {
      const entry = byPort.get(result.port) ?? { result, addresses: [] };
      entry.addresses.push(result.address);
      byPort.set(result.port, entry);
    }
  }
  for (const [port, { result, addresses }] of byPort) {
    out.push(
      finding("portExposed", result.severity as ExposureSeverity, stage, String(port), {
        port,
        service: result.service,
        category: result.category,
        addresses: addresses.slice(0, 4).join(", "),
      }),
    );
  }
  const tlsByKey = new Map<string, FindingDraft>();
  for (const result of snapshot.open) {
    // Port 443 is judged by stage 1 already; this keeps stage 2 to the other TLS ports.
    if (!result.tls || result.service === "https") continue;
    for (const f of tlsFindings(result.tls, now, stage)) {
      const key = `${f.rule}|${f.subject}`;
      const known = tlsByKey.get(key);
      if (!known || SEVERITY_RANK[f.severity] > SEVERITY_RANK[known.severity]) tlsByKey.set(key, f);
    }
  }
  out.push(...tlsByKey.values());
  return out;
}

/** Counts findings per severity. */
export function countBySeverity(
  findings: readonly { severity: ExposureSeverity }[],
): Record<ExposureSeverity, number> {
  const counts: Record<ExposureSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

/** Which ports are open now that were not open in the previous run (compared per address and port). */
export function newOpenPorts(
  now: readonly { address: string; port: number }[],
  previous: readonly { address: string; port: number }[],
): { address: string; port: number }[] {
  const before = new Set(previous.map((p) => `${p.address}|${p.port}`));
  return now.filter((p) => !before.has(`${p.address}|${p.port}`));
}
