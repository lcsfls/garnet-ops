/**
 * What an admin may add as an external asset (ADR 0023), and which addresses GarnetOps may ever connect to for it.
 *
 * Only public names and public addresses are accepted: the whole feature looks at the organisation from the outside, so a
 * private, loopback, link-local, documentation or otherwise reserved address is never a valid asset and never a connection
 * target. The same address policy runs again in the worker for every address a name resolves to (DNS can change between the
 * two), which is the authoritative check.
 */
import { randomBytes } from "node:crypto";
import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import { classifyAddress, inNetwork } from "./ai-endpoint.ts";
import { canonicalIp } from "./geoip.ts";

export type AssetProblem =
  | "empty"
  | "tooLong"
  | "url"
  | "wildcard"
  | "characters"
  | "label"
  | "singleLabel"
  | "numericTld"
  | "reservedName"
  | "notPublic";

export type AssetCheck =
  | { ok: true; kind: "domain" | "ip"; value: string }
  | { ok: false; problem: AssetProblem };

/** Suffixes that never name a public host: private zones, loopback names and the names reserved for documentation and tests. */
const NON_PUBLIC_SUFFIXES = new Set([
  "localhost",
  "local",
  "localdomain",
  "internal",
  "intranet",
  "lan",
  "home",
  "corp",
  "private",
  "test",
  "invalid",
  "onion",
  "arpa",
  "example",
]);

/**
 * Ranges that are not private in the RFC 1918 sense but are not reachable on the internet either: documentation networks,
 * benchmarking, IETF protocol assignments, and the IPv6 documentation prefixes. `classifyAddress` calls them "public"; an
 * external asset must not be one of them.
 */
const SPECIAL_NETWORKS = [
  "192.0.0.0/24",
  "192.0.2.0/24",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "192.88.99.0/24",
  "2001:db8::/32",
  "3fff::/20",
  "2001::/23",
  "64:ff9b:1::/48",
  "100::/64",
  // Translation and tunnel forms carry an IPv4 address: an asset is written as the address itself.
  "64:ff9b::/96",
  "2002::/16",
];

/** Whether an address may be an external asset or a connection target: public, and not in a special-purpose range. */
export function isExternalAddress(address: string): boolean {
  if (classifyAddress(address) !== "public") return false;
  return !SPECIAL_NETWORKS.some((net) => inNetwork(address, net));
}

/**
 * The address policy of a run. Production is {@link isExternalAddress}. `allowTestRanges` exists for tests only (a fake server
 * listens on loopback); production code never sets it and the API ignores it outside `NODE_ENV=test`.
 */
export function addressAllowed(address: string, allowTestRanges = false): boolean {
  // Tests open loopback and the documentation ranges, nothing else: private, link-local and metadata addresses stay refused.
  if (allowTestRanges) return classifyAddress(address) === "public" || isLoopbackLike(address);
  return isExternalAddress(address);
}

function isLoopbackLike(address: string): boolean {
  return classifyAddress(address, true) === "private" && classifyAddress(address, false) === "forbidden";
}

/**
 * Checks and normalises what an admin typed. A host name (RFC 1123: letters, digits and hyphens, labels of 1 to 63 characters,
 * 253 in all, at least two labels, a TLD that is not all digits, none of the non-public suffixes) is lower-cased with the
 * trailing dot removed and internationalised names converted to their ASCII form. An address must be public.
 */
export function checkAsset(raw: string, options: { allowTestRanges?: boolean } = {}): AssetCheck {
  let text = raw.trim();
  if (text.length === 0) return { ok: false, problem: "empty" };
  if (text.length > 300) return { ok: false, problem: "tooLong" };
  if (/[/\\?#@\s]|:\/\//.test(text)) return { ok: false, problem: "url" };
  if (text.includes("*")) return { ok: false, problem: "wildcard" };

  const literal = text.replace(/^\[|\]$/g, "");
  const ipKind = isIP(literal);
  if (ipKind !== 0) {
    const canonical = canonicalIp(literal);
    if (!canonical || (ipKind === 6 && /^::ffff:/i.test(literal))) return { ok: false, problem: "notPublic" };
    if (!addressAllowed(canonical, options.allowTestRanges === true)) {
      return { ok: false, problem: "notPublic" };
    }
    return { ok: true, kind: "ip", value: canonical };
  }
  if (text.includes(":")) return { ok: false, problem: "characters" };

  text = text.replace(/\.$/, "");
  const ascii = /^[\x20-\x7e]+$/.test(text) ? text.toLowerCase() : domainToASCII(text);
  if (!ascii) return { ok: false, problem: "characters" };
  if (ascii.length > 253) return { ok: false, problem: "tooLong" };
  const labels = ascii.split(".");
  if (labels.length < 2) return { ok: false, problem: "singleLabel" };
  for (const label of labels) {
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) return { ok: false, problem: "label" };
  }
  const tld = labels[labels.length - 1] as string;
  // 127.1, 0x7f.1 and 0x7f.0x1 are read as IPv4 addresses by many resolvers: they are no host names.
  if (/^(\d+|0x[0-9a-f]*)$/i.test(tld)) return { ok: false, problem: "numericTld" };
  if (tld.startsWith("xn--") ? tld.length < 6 : tld.length < 2) return { ok: false, problem: "label" };
  if (NON_PUBLIC_SUFFIXES.has(tld) || ascii === "home.arpa") return { ok: false, problem: "reservedName" };
  return { ok: true, kind: "domain", value: ascii };
}

/** A fresh proof token: 256 random bits as 43 base64url characters. */
export function newVerifyToken(): string {
  return randomBytes(32).toString("base64url");
}
