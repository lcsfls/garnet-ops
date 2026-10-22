/**
 * LDAP and Active Directory sign-in (ADR 0020): the pure rules. Everything that decides what a
 * directory may do to GarnetOps lives here and has no I/O, so it can be tested without a server:
 * what an admin may configure, how a user name becomes a search filter without becoming
 * filter syntax, how distinguished names are compared, which group gives which role, and how
 * the directory's immutable unique id is read.
 *
 * Directory content is hostile input. A user name is typed by anyone who can reach the sign-in
 * page; names, group lists and attribute values come from a server we do not control.
 *
 * Keep this file free of Node-only imports: the web app imports it too (presets, limits).
 */
import type { Role } from "./index.ts";

/* -------------------------------------------------------------------------- */
/* Roles                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * The roles a directory group can give. "owner" is never one of them: owners are local accounts
 * only, so an LDAP outage or a changed group can never lock the installation out, and nobody can
 * become an owner by being put into a group.
 */
export const DIRECTORY_ROLES = ["admin", "member", "viewer"] as const;
export type DirectoryRole = (typeof DIRECTORY_ROLES)[number];

const ROLE_RANK: Record<DirectoryRole, number> = { viewer: 0, member: 1, admin: 2 };

export const isDirectoryRole = (value: unknown): value is DirectoryRole =>
  typeof value === "string" && (DIRECTORY_ROLES as readonly string[]).includes(value);

/** Whether an account with this role may be linked to a directory identity (owners may not). */
export const mayLinkRole = (role: Role): role is DirectoryRole => role !== "owner";

/* -------------------------------------------------------------------------- */
/* Limits and defaults                                                         */
/* -------------------------------------------------------------------------- */

export const DIRECTORY_LIMITS = {
  /** Servers to try in order. */
  maxServers: 4,
  maxGroupRoles: 50,
  maxDnLength: 1000,
  maxFilterLength: 500,
  maxCaPemLength: 64 * 1024,
  usernameMax: 128,
  /** A passphrase can be long; anything longer is refused without being sent anywhere. */
  passwordMax: 512,
  bindPasswordMax: 512,
  connectTimeoutSeconds: { min: 1, max: 30, default: 5 },
  operationTimeoutSeconds: { min: 1, max: 60, default: 10 },
  sizeLimit: { min: 2, max: 1000, default: 50 },
} as const;

export const DIRECTORY_PRESETS = ["active-directory", "openldap", "custom"] as const;
export type DirectoryPreset = (typeof DIRECTORY_PRESETS)[number];

/** How group membership is read. See {@link DirectoryGroupMode}. */
export const GROUP_MODES = ["member-of", "nested", "search"] as const;
/**
 * - `member-of`: the user entry's `memberOf` attribute (direct memberships; Active Directory,
 *   or OpenLDAP with the memberof overlay).
 * - `nested`: Active Directory's matching rule in chain (1.2.840.113556.1.4.1941), which the
 *   server evaluates through nested groups.
 * - `search`: each allowed group is searched for the user with a filter (OpenLDAP
 *   `groupOfNames`/`groupOfUniqueNames`, or `posixGroup` with `memberUid`).
 */
export type DirectoryGroupMode = (typeof GROUP_MODES)[number];

/** Active Directory's LDAP_MATCHING_RULE_IN_CHAIN. */
export const AD_CHAIN_RULE = "1.2.840.113556.1.4.1941";

export const TLS_TRUSTS = ["system", "ca", "pin"] as const;
/** `system`: the worker's certificate store; `ca`: only the pasted CA certificate(s); `pin`: the SHA-256 of the leaf. */
export type DirectoryTlsTrust = (typeof TLS_TRUSTS)[number];

export interface DirectoryPresetValues {
  userFilter: string;
  emailAttribute: string;
  nameAttribute: string;
  uniqueIdAttribute: string;
  groupMode: DirectoryGroupMode;
  groupFilter: string;
}

export const DIRECTORY_PRESET_VALUES: Record<DirectoryPreset, DirectoryPresetValues> = {
  "active-directory": {
    userFilter: "(&(objectClass=user)(sAMAccountName={username}))",
    emailAttribute: "mail",
    nameAttribute: "displayName",
    uniqueIdAttribute: "objectGUID",
    groupMode: "nested",
    groupFilter: "",
  },
  openldap: {
    userFilter: "(&(objectClass=inetOrgPerson)(uid={username}))",
    emailAttribute: "mail",
    nameAttribute: "cn",
    uniqueIdAttribute: "entryUUID",
    groupMode: "search",
    groupFilter: "(|(member={dn})(uniqueMember={dn}))",
  },
  custom: {
    userFilter: "",
    emailAttribute: "mail",
    nameAttribute: "cn",
    uniqueIdAttribute: "entryUUID",
    groupMode: "member-of",
    groupFilter: "",
  },
};

/** Default filter of the `search` group mode. */
export const DEFAULT_GROUP_FILTER = DIRECTORY_PRESET_VALUES.openldap.groupFilter;

/* -------------------------------------------------------------------------- */
/* Filters                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Escapes a value for use inside an LDAP search filter (RFC 4515, section 3): the characters
 * with a meaning in filters (`*`, `(`, `)`, `\`, NUL) and all other control characters become
 * `\xx`. Non-ASCII text stays as it is (UTF-8, allowed by the RFC). A value can therefore never
 * end a filter item, open another one or become a wildcard.
 */
export function escapeFilterValue(value: string): string {
  let out = "";
  for (const char of value) {
    const code = char.codePointAt(0) as number;
    if (code < 0x20 || code === 0x7f || char === "*" || char === "(" || char === ")" || char === "\\") {
      out += `\\${code.toString(16).padStart(2, "0")}`;
    } else {
      out += char;
    }
  }
  return out;
}

const PLACEHOLDER = /\{([a-z]+)\}/g;

export type FilterProblem = "empty" | "tooLong" | "syntax" | "placeholder" | "missingPlaceholder";

/**
 * Checks a filter template an admin typed: well-formed RFC 4515 syntax after the placeholders
 * are replaced by a harmless value, only the placeholders in `allowed`, and every one in
 * `required` present. Returns the problem or null.
 */
export function filterTemplateProblem(
  template: string,
  options: { allowed: readonly string[]; required: readonly string[] },
): FilterProblem | null {
  if (template.length === 0) return "empty";
  if (template.length > DIRECTORY_LIMITS.maxFilterLength) return "tooLong";
  // biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are what is refused here
  if (/[\u0000-\u001f\u007f]/.test(template)) return "syntax";
  const used = new Set<string>();
  const probe = template.replace(PLACEHOLDER, (_m, name: string) => {
    used.add(name);
    return "x";
  });
  if (/[{}]/.test(probe)) return "placeholder";
  for (const name of used) if (!options.allowed.includes(name)) return "placeholder";
  for (const name of options.required) if (!used.has(name)) return "missingPlaceholder";
  return isValidFilter(probe) ? null : "syntax";
}

/**
 * RFC 4515 filter syntax: `(attr=value)`, `(attr=*)`, substrings, `(&…)`, `(|…)`, `(!…)` and
 * extensible matches `(attr:dn:rule:=value)`. Values may contain `\xx` escapes; a bare `\`, `(`
 * or `)` inside a value is a syntax error. Depth is limited so a pathological filter cannot
 * exhaust the stack.
 */
export function isValidFilter(filter: string): boolean {
  let pos = 0;
  const item =
    // biome-ignore lint/suspicious/noControlCharactersInRegex: refusing a NUL byte in a filter value is the point
    /^(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)*)?(?::dn)?(?::[0-9]+(?:\.[0-9]+)*|:[A-Za-z][A-Za-z0-9-]*)?(?:=|~=|>=|<=|:=)(?:[^()\\\u0000]|\\[0-9a-fA-F]{2})*$/;

  function parseFilter(depth: number): boolean {
    if (depth > 12 || filter[pos] !== "(") return false;
    pos++;
    const head = filter[pos];
    let ok: boolean;
    if (head === "&" || head === "|") {
      pos++;
      let count = 0;
      while (filter[pos] === "(") {
        if (!parseFilter(depth + 1)) return false;
        count++;
      }
      ok = count > 0;
    } else if (head === "!") {
      pos++;
      ok = parseFilter(depth + 1);
    } else {
      const end = filter.indexOf(")", pos);
      // A value cannot contain ")" unescaped, so the item ends at the next one.
      if (end === -1) return false;
      const text = filter.slice(pos, end);
      // "(" cannot appear in an item either, or it would be a nested filter written wrongly.
      ok = !text.includes("(") && text.length > 0 && item.test(text) && !text.startsWith("=");
      pos = end;
    }
    if (!ok || filter[pos] !== ")") return false;
    pos++;
    return true;
  }

  return parseFilter(0) && pos === filter.length;
}

/**
 * Fills a filter template. Each `{name}` is replaced by the escaped value in a single pass, so
 * a value that itself looks like `{dn}` is not expanded again. Throws on a placeholder without
 * a value: the template was checked when it was saved, so that is a bug, not user input.
 */
export function renderFilter(template: string, values: Record<string, string>): string {
  return template.replace(PLACEHOLDER, (_m, name: string) => {
    const value = values[name];
    if (value === undefined) throw new Error(`No value for filter placeholder ${name}`);
    return escapeFilterValue(value);
  });
}

/* -------------------------------------------------------------------------- */
/* What a person types at sign-in                                              */
/* -------------------------------------------------------------------------- */

/**
 * A directory user name: a letter or digit first, then letters, digits and `. _ @ \ ' + -`. That
 * covers `jdoe`, `j.doe`, `jdoe@example.lan` and `EXAMPLE\jdoe` and keeps out everything that
 * has a meaning in LDAP filters or DNs (`* ( ) = , ; < > " #`), whitespace and control
 * characters. Unicode letters are allowed. The filter escaping above is the control; this is
 * a second wall and an early, cheap refusal.
 */
export const USERNAME_PATTERN = /^[\p{L}\p{N}][\p{L}\p{N}._@\\'+-]*$/u;

export function checkUsername(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const name = value.normalize("NFC").trim();
  if (name.length === 0 || name.length > DIRECTORY_LIMITS.usernameMax) return null;
  return USERNAME_PATTERN.test(name) ? name : null;
}

/**
 * The password typed at sign-in. It must not be empty: a simple bind with a name and an empty
 * password is an "unauthenticated bind" (RFC 4513, section 5.1.2) that many servers answer with
 * success, which would sign anyone in. NUL bytes are refused as well.
 */
export function checkPassword(value: unknown): string | null {
  if (typeof value !== "string") return null;
  if (value.length === 0 || value.length > DIRECTORY_LIMITS.passwordMax) return null;
  return value.includes("\u0000") ? null : value;
}

/** The key under which attempts for a user name are counted: case-insensitive, no domain tricks. */
export function usernameKey(username: string): string {
  return username.normalize("NFC").toLowerCase();
}

/* -------------------------------------------------------------------------- */
/* Distinguished names                                                         */
/* -------------------------------------------------------------------------- */

export interface DnAttribute {
  type: string;
  value: string;
}
/** A relative distinguished name: one or more attribute values (`cn=a+uid=b`), sorted by type. */
export type Rdn = DnAttribute[];

const DN_TYPE = /^(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)*)$/;
const HEX = /^[0-9a-fA-F]{2}$/;

/** Splits at every `sep` that is not escaped (and not inside a `\xx` pair). */
function splitUnescaped(text: string, sep: string): string[] | null {
  const parts: string[] = [];
  let current = "";
  for (let i = 0; i < text.length; i++) {
    const char = text[i] as string;
    if (char === "\\") {
      if (i + 1 >= text.length) return null;
      current += char + (text[i + 1] as string);
      i++;
    } else if (char === sep) {
      parts.push(current);
      current = "";
    } else {
      current += char;
    }
  }
  parts.push(current);
  return parts;
}

/** Decodes the escapes of an RFC 4514 attribute value; null if it is malformed. */
function unescapeDnValue(raw: string): string | null {
  if (raw.startsWith("#")) return /^#(?:[0-9a-fA-F]{2})+$/.test(raw) ? raw.toLowerCase() : null;
  if (raw.startsWith('"')) return null; // the obsolete quoted form (RFC 2253) is not accepted
  const bytes: number[] = [];
  const encoder = new TextEncoder();
  for (let i = 0; i < raw.length; i++) {
    const char = raw[i] as string;
    if (char === "\\") {
      const next = raw[i + 1];
      if (next === undefined) return null;
      const pair = raw.slice(i + 1, i + 3);
      if (HEX.test(pair)) {
        bytes.push(Number.parseInt(pair, 16));
        i += 2;
        continue;
      }
      if (!',+"\\<>; =#'.includes(next)) return null;
      bytes.push(...encoder.encode(next));
      i += 1;
      continue;
    }
    // Unescaped special characters are not allowed in a value.
    if ('"<>;'.includes(char)) return null;
    bytes.push(...encoder.encode(char));
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(new Uint8Array(bytes));
  } catch {
    return null;
  }
}

/** Removes spaces at the end of `text` unless the last one is escaped (`\ `). */
function trimUnescapedEnd(text: string): string {
  let end = text.length;
  while (end > 0 && text[end - 1] === " ") {
    let slashes = 0;
    while (end - 2 - slashes >= 0 && text[end - 2 - slashes] === "\\") slashes++;
    if (slashes % 2 === 1) break;
    end--;
  }
  return text.slice(0, end);
}

/**
 * Parses a distinguished name (RFC 4514). Returns the RDNs from the leaf to the root, or null
 * for anything that is not a well-formed DN, so a malformed value can never be "compared equal"
 * to a good one. The empty string is the root DSE and parses to an empty list.
 */
export function parseDn(dn: string): Rdn[] | null {
  if (dn.length > DIRECTORY_LIMITS.maxDnLength) return null;
  if (dn.length === 0) return [];
  const rdns = splitUnescaped(dn, ",");
  if (!rdns) return null;
  const out: Rdn[] = [];
  for (const rdnText of rdns) {
    const avas = splitUnescaped(rdnText, "+");
    if (!avas) return null;
    const rdn: Rdn = [];
    for (const ava of avas) {
      const eq = ava.indexOf("=");
      if (eq <= 0) return null;
      const type = ava.slice(0, eq).trim();
      if (!DN_TYPE.test(type)) return null;
      // Spaces around the separators are not part of the value (RFC 4514 requires them escaped).
      const value = unescapeDnValue(trimUnescapedEnd(ava.slice(eq + 1).replace(/^ +/, "")));
      if (value === null) return null;
      rdn.push({ type: type.toLowerCase(), value });
    }
    rdn.sort((a, b) => (a.type === b.type ? a.value.localeCompare(b.value) : a.type.localeCompare(b.type)));
    out.push(rdn);
  }
  return out;
}

const canonicalValue = (value: string) => value.normalize("NFC").toLowerCase();

/**
 * A canonical form for comparing DNs: attribute types lower-case, values case-folded (Active
 * Directory and the usual LDAP servers compare names case-insensitively), spacing and escaping
 * removed, multi-valued RDNs ordered. Null if `dn` is not a valid DN.
 */
export function normalizeDn(dn: string): string | null {
  const rdns = parseDn(dn);
  if (!rdns) return null;
  return rdns
    .map((rdn) => rdn.map((a) => `${a.type}=${JSON.stringify(canonicalValue(a.value))}`).join("+"))
    .join(",");
}

/** Whether two DNs name the same entry. Invalid DNs never match anything. */
export function sameDn(a: string, b: string): boolean {
  const x = normalizeDn(a);
  const y = normalizeDn(b);
  return x !== null && y !== null && x === y;
}

/** Whether `dn` is `base` or below it. Invalid DNs are never below anything. */
export function isUnderDn(dn: string, base: string): boolean {
  const x = parseDn(dn);
  const y = parseDn(base);
  if (!x || !y || y.length > x.length) return false;
  const tail = (list: Rdn[]) =>
    list.map((rdn) => rdn.map((a) => `${a.type}=${canonicalValue(a.value)}`).join("+"));
  const xs = tail(x);
  const ys = tail(y);
  return ys.every((rdn, i) => rdn === xs[xs.length - ys.length + i]);
}

/* -------------------------------------------------------------------------- */
/* Groups and roles                                                            */
/* -------------------------------------------------------------------------- */

export interface GroupRole {
  dn: string;
  role: DirectoryRole;
}

/** The highest role (admin over member over viewer) of the groups a user is in, or null if in none. */
export function roleForGroups(
  memberOf: Iterable<string>,
  mappings: readonly GroupRole[],
): DirectoryRole | null {
  const have = new Set<string>();
  for (const dn of memberOf) {
    const n = normalizeDn(dn);
    if (n !== null) have.add(n);
  }
  let best: DirectoryRole | null = null;
  for (const mapping of mappings) {
    // Whatever is stored, only these three roles can come out: a hand-edited "owner" is ignored.
    if (!isDirectoryRole(mapping.role)) continue;
    const n = normalizeDn(mapping.dn);
    if (n === null || !have.has(n)) continue;
    if (best === null || ROLE_RANK[mapping.role] > ROLE_RANK[best]) best = mapping.role;
  }
  return best;
}

/** The configured groups a user is in, as written in the configuration (for the test result and the audit log). */
export function matchedGroups(memberOf: Iterable<string>, mappings: readonly GroupRole[]): string[] {
  const have = new Set<string>();
  for (const dn of memberOf) {
    const n = normalizeDn(dn);
    if (n !== null) have.add(n);
  }
  return mappings.filter((m) => have.has(normalizeDn(m.dn) ?? "\u0000")).map((m) => m.dn);
}

/* -------------------------------------------------------------------------- */
/* The directory's immutable id                                                */
/* -------------------------------------------------------------------------- */

/**
 * Reads the immutable unique id of an entry. Accounts are linked by this id, never by mail
 * address, so changing a mail attribute can not take over another person's account.
 *
 * `objectGUID` is 16 bytes in Microsoft's mixed byte order and becomes the usual GUID text.
 * `entryUUID` and similar are text already (also when a client hands them over as bytes). Other
 * binary values are hex. The result is lower-case, 1 to 128 characters, or null.
 */
export function readUniqueId(attribute: string, value: unknown): string | null {
  const first = Array.isArray(value) ? value[0] : value;
  if (first === undefined || first === null) return null;
  let id: string;
  if (typeof first === "string") {
    id = first.trim().toLowerCase();
  } else if (first instanceof Uint8Array) {
    if (first.length === 0) return null;
    const hex = () => Array.from(first, (n) => n.toString(16).padStart(2, "0"));
    if (attribute.toLowerCase() === "objectguid" && first.length === 16) {
      const b = hex();
      id = [[b[3], b[2], b[1], b[0]], [b[5], b[4]], [b[7], b[6]], [b[8], b[9]], b.slice(10)]
        .map((part) => part.join(""))
        .join("-");
    } else {
      // A client may hand over text attributes (entryUUID) as bytes: printable text stays text, anything else is hex.
      let text: string | null = null;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(first);
      } catch {
        text = null;
      }
      // biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are what is refused here
      id = text !== null && !/[\u0000-\u001f\u007f]/.test(text) ? text.trim().toLowerCase() : hex().join("");
    }
  } else {
    return null;
  }
  // biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are what is refused here
  return id.length === 0 || id.length > 128 || /[\u0000-\u001f\u007f]/.test(id) ? null : id;
}

/** The first text value of an attribute, trimmed and capped; null if there is none. */
export function readText(value: unknown, max = 256): string | null {
  const first = Array.isArray(value) ? value[0] : value;
  if (typeof first !== "string") return null;
  // biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are what is removed here
  const text = first.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  return text.length === 0 ? null : text.slice(0, max);
}

const EMAIL = /^[^\s@<>()[\]\\,;:"]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;

/** A mail address from the directory, lower-case; null if it is not plausible. The directory is not trusted to be tidy. */
export function readEmail(value: unknown): string | null {
  const text = readText(value, 254);
  if (!text) return null;
  const email = text.toLowerCase();
  return EMAIL.test(email) && email.includes(".", email.indexOf("@")) ? email : null;
}

/* -------------------------------------------------------------------------- */
/* Settings                                                                    */
/* -------------------------------------------------------------------------- */

const ATTRIBUTE = /^[A-Za-z][A-Za-z0-9-]{0,63}$/;
export const isAttributeName = (value: string) => ATTRIBUTE.test(value);

/** The settings an admin saves. The bind password is separate (write-only). */
export interface DirectorySettings {
  enabled: boolean;
  preset: DirectoryPreset;
  /** `ldaps://host[:port]` or `ldap://host[:port]` (StartTLS is then mandatory). */
  servers: string[];
  tlsTrust: DirectoryTlsTrust;
  /** PEM certificate(s) for `tlsTrust = ca`. */
  caCertificate: string;
  bindDn: string;
  userBaseDn: string;
  userFilter: string;
  emailAttribute: string;
  nameAttribute: string;
  uniqueIdAttribute: string;
  groupMode: DirectoryGroupMode;
  groupFilter: string;
  groupRoles: GroupRole[];
  /** Whether the directory is trusted to have verified the mail address (see ADR 0020). */
  emailVerified: boolean;
  connectTimeoutSeconds: number;
  operationTimeoutSeconds: number;
  sizeLimit: number;
}

export interface SettingsProblem {
  field: string;
  code: string;
}

export type ServerUrlCheck =
  | { ok: true; url: string; scheme: "ldaps" | "ldap"; host: string; port: number }
  | { ok: false; problem: "scheme" | "syntax" | "credentials" | "path" | "port" | "host" };

/**
 * Checks and normalises a server URL. Only `ldaps://` (default port 636) and `ldap://`
 * (default 389, always upgraded with StartTLS before anything secret is sent) are accepted.
 * No user name, path, query or fragment. The host must pass `checkHost`, which the caller
 * supplies (the address policy lives in hosts.ts, which this file must not import).
 */
export function checkServerUrl(value: string, checkHost: (host: string) => string | null): ServerUrlCheck {
  const text = value.trim();
  const match = /^(ldaps|ldap):\/\/([^/?#@\s]+)$/i.exec(text);
  if (!match) {
    if (/^(ldaps|ldap):\/\//i.test(text)) {
      return { ok: false, problem: /[@]/.test(text) ? "credentials" : "path" };
    }
    return { ok: false, problem: /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? "scheme" : "syntax" };
  }
  const scheme = (match[1] as string).toLowerCase() as "ldaps" | "ldap";
  const authority = match[2] as string;
  let hostText = authority;
  let portText: string | null = null;
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end === -1) return { ok: false, problem: "syntax" };
    hostText = authority.slice(1, end);
    const rest = authority.slice(end + 1);
    if (rest !== "") {
      if (!rest.startsWith(":")) return { ok: false, problem: "syntax" };
      portText = rest.slice(1);
    }
  } else {
    const colon = authority.lastIndexOf(":");
    if (colon !== -1) {
      hostText = authority.slice(0, colon);
      portText = authority.slice(colon + 1);
    }
  }
  let port = scheme === "ldaps" ? 636 : 389;
  if (portText !== null) {
    if (!/^\d{1,5}$/.test(portText)) return { ok: false, problem: "port" };
    port = Number(portText);
    if (port < 1 || port > 65535) return { ok: false, problem: "port" };
  }
  const host = checkHost(hostText);
  if (host === null) return { ok: false, problem: "host" };
  const shown = host.includes(":") ? `[${host}]` : host;
  const defaultPort = scheme === "ldaps" ? 636 : 389;
  return {
    ok: true,
    scheme,
    host,
    port,
    url: `${scheme}://${shown}${port === defaultPort ? "" : `:${port}`}`,
  };
}

/** Whether the text holds at least one PEM certificate and nothing else that looks like a key. */
export function caCertificateProblem(pem: string): "empty" | "tooLong" | "syntax" | "privateKey" | null {
  const text = pem.trim();
  if (text.length === 0) return "empty";
  if (text.length > DIRECTORY_LIMITS.maxCaPemLength) return "tooLong";
  if (/PRIVATE KEY/.test(text)) return "privateKey";
  const blocks = text.match(/-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----/g) ?? [];
  if (blocks.length === 0) return "syntax";
  const rest = blocks.reduce((acc, block) => acc.replace(block, ""), text).trim();
  return rest.length === 0 ? null : "syntax";
}

/**
 * Validates the settings an admin saves. Returns the problems by field and code; the web app
 * maps the codes to its own messages. `checkHost` is the address policy (see checkServerUrl).
 */
export function checkDirectorySettings(
  input: DirectorySettings,
  checkHost: (host: string) => string | null,
): { problems: SettingsProblem[]; servers: string[] } {
  const problems: SettingsProblem[] = [];
  const add = (field: string, code: string) => problems.push({ field, code });

  const servers: string[] = [];
  if (input.servers.length === 0) add("servers", "empty");
  if (input.servers.length > DIRECTORY_LIMITS.maxServers) add("servers", "tooMany");
  for (const [index, raw] of input.servers.entries()) {
    const checked = checkServerUrl(raw, checkHost);
    if (!checked.ok) add(`servers.${index}`, `url_${checked.problem}`);
    else if (servers.includes(checked.url)) add(`servers.${index}`, "url_duplicate");
    else servers.push(checked.url);
  }

  if (input.tlsTrust === "ca") {
    const problem = caCertificateProblem(input.caCertificate);
    if (problem) add("caCertificate", `ca_${problem}`);
  }

  const dn = (field: string, value: string, allowEmpty = false) => {
    if (value.length === 0 && allowEmpty) return;
    if (value.length === 0) return add(field, "dn_empty");
    if (parseDn(value) === null || value.length > DIRECTORY_LIMITS.maxDnLength) add(field, "dn_invalid");
  };
  dn("bindDn", input.bindDn);
  dn("userBaseDn", input.userBaseDn);

  const userFilter = filterTemplateProblem(input.userFilter, {
    allowed: ["username"],
    required: ["username"],
  });
  if (userFilter) add("userFilter", `filter_${userFilter}`);

  for (const [field, value] of [
    ["emailAttribute", input.emailAttribute],
    ["nameAttribute", input.nameAttribute],
    ["uniqueIdAttribute", input.uniqueIdAttribute],
  ] as const) {
    if (!isAttributeName(value)) add(field, "attribute_invalid");
  }

  if (input.groupMode === "search") {
    const groupFilter = filterTemplateProblem(input.groupFilter, {
      allowed: ["dn", "username"],
      required: ["dn"],
    });
    if (groupFilter) add("groupFilter", `filter_${groupFilter}`);
  }

  if (input.groupRoles.length === 0) add("groupRoles", "empty");
  if (input.groupRoles.length > DIRECTORY_LIMITS.maxGroupRoles) add("groupRoles", "tooMany");
  const seen = new Set<string>();
  for (const [index, entry] of input.groupRoles.entries()) {
    const normalized = normalizeDn(entry.dn);
    if (normalized === null || normalized === "") add(`groupRoles.${index}`, "dn_invalid");
    else if (!isDirectoryRole(entry.role)) add(`groupRoles.${index}`, "role_invalid");
    else if (seen.has(normalized)) add(`groupRoles.${index}`, "dn_duplicate");
    else seen.add(normalized);
  }

  const limits = DIRECTORY_LIMITS;
  const within = (field: string, value: number, range: { min: number; max: number }) => {
    if (!Number.isInteger(value) || value < range.min || value > range.max) add(field, "range");
  };
  within("connectTimeoutSeconds", input.connectTimeoutSeconds, limits.connectTimeoutSeconds);
  within("operationTimeoutSeconds", input.operationTimeoutSeconds, limits.operationTimeoutSeconds);
  within("sizeLimit", input.sizeLimit, limits.sizeLimit);

  return { problems, servers };
}

/* -------------------------------------------------------------------------- */
/* Results the worker stores                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Why a directory operation did not work. The codes are for the admin (test result, audit
 * log); the person signing in only ever sees one generic message.
 */
export const DIRECTORY_PROBLEMS = [
  "not-configured",
  "disabled",
  "certificate-not-confirmed",
  "certificate-changed",
  "tls-failed",
  "starttls-refused",
  "address-refused",
  "unresolvable",
  "unreachable",
  "timeout",
  "service-bind-failed",
  "service-bind-blocked",
  "base-not-found",
  "search-failed",
  "user-not-found",
  "user-ambiguous",
  "user-outside-base",
  "no-unique-id",
  "no-email",
  "wrong-password",
  "group-search-failed",
  "not-in-group",
  "internal",
] as const;
export type DirectoryProblem = (typeof DIRECTORY_PROBLEMS)[number];

export type SignInOutcome = "ok" | "invalid-credentials" | "not-allowed" | "unavailable" | "misconfigured";

/** What the directory said about one person. Never contains a password. */
export interface DirectoryUser {
  uniqueId: string;
  dn: string;
  email: string | null;
  name: string | null;
  /** The configured groups the person is in, as configured. */
  groups: string[];
  role: DirectoryRole | null;
}

export interface SignInResult {
  outcome: SignInOutcome;
  /** Admin-facing reason; the person signing in never sees it. */
  problem?: DirectoryProblem;
  user?: DirectoryUser;
  /** Who a refused password was tried for (the directory entry), so the audit log can name them instead of the typed text. */
  subject?: { dn: string; uniqueId: string };
}

export interface CertificateFacts {
  fingerprint: string;
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  /** The certificate also verifies against the trust that is configured (informational). */
  trusted: boolean;
}

export interface TestResult {
  ok: boolean;
  problem?: DirectoryProblem;
  servers: {
    url: string;
    ok: boolean;
    problem?: DirectoryProblem;
    /** A Node error code of a TLS or socket failure (`CERT_HAS_EXPIRED`); safe to show an admin. */
    detail?: string;
    /** `ldaps` or `starttls`. */
    transport: "ldaps" | "starttls";
    certificate?: CertificateFacts;
  }[];
  user?: DirectoryUser;
  /** Per configured group: whether it exists, and whether the test user is in it. */
  groups?: { dn: string; exists: boolean; member: boolean }[];
  latencyMs: number;
}
