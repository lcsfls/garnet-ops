/**
 * Certificate Transparency lookups for external exposure (ADR 0023), the one place where this feature sends a domain name to a third
 * party. It is opt-in per organisation, runs only for verified domains, at most once a day per asset, within a daily budget and with
 * a pause between requests, and it only ever reads.
 *
 * The provider is crt.sh (operated by Sectigo), a public search over the CT logs. The request goes to the fixed host over HTTPS with
 * the system certificate store, through the same address-checked client as the other opt-in downloads (outbound.ts): a poisoned DNS
 * answer cannot aim it at the internal network, redirects are errors, the answer is size-capped. What it returns is hostile text: only
 * names that are valid host names below the queried domain are kept, and they are suggestions that nothing connects to.
 *
 * crt.sh publishes no API terms or service level that we could confirm; the documentation says so and the setting says that data
 * leaves the network. Another provider only needs the `CtFetch` shape.
 */
import { CT_LIMITS, CT_PROVIDER, ctPath } from "@garnetops/core/exposure";
import { checkAsset } from "@garnetops/core/exposure-assets";
import { httpsGet, type Lookup, OutboundError, readCapped } from "./outbound.ts";

export type CtErrorCode =
  | "unreachable"
  | "timeout"
  | "tooLarge"
  | "invalidResponse"
  | "httpStatus"
  | "refusedAddress";

export class CtError extends Error {
  readonly code: CtErrorCode;
  constructor(code: CtErrorCode) {
    super(code);
    this.name = "CtError";
    this.code = code;
  }
}

/** Looks up the names below a domain. Tests replace it. */
export type CtFetch = (domain: string) => Promise<string[]>;

/** The host names in a crt.sh JSON answer that are valid and below `domain` (not the domain itself), lower-case, sorted, capped. */
export function parseCtNames(body: string, domain: string): string[] {
  let data: unknown;
  try {
    data = JSON.parse(body);
  } catch {
    throw new CtError("invalidResponse");
  }
  if (!Array.isArray(data)) throw new CtError("invalidResponse");
  const names = new Set<string>();
  for (const entry of data) {
    if (typeof entry !== "object" || entry === null) continue;
    const record = entry as Record<string, unknown>;
    for (const field of [record.name_value, record.common_name]) {
      if (typeof field !== "string") continue;
      for (const line of field.split("\n").slice(0, 200)) {
        const candidate = line.trim().toLowerCase().replace(/^\*\./, "");
        if (candidate === domain || !candidate.endsWith(`.${domain}`)) continue;
        const checked = checkAsset(candidate);
        if (checked.ok && checked.kind === "domain") names.add(checked.value);
        if (names.size >= CT_LIMITS.maxNames * 2) break;
      }
    }
  }
  return [...names].sort().slice(0, CT_LIMITS.maxNames);
}

/**
 * The real lookup. `lookup` resolves crt.sh through the organisation's public DNS as well; `test` points it at a local server
 * (tests only).
 */
export function crtShFetch(test?: { lookup?: Lookup; ca?: string; port?: number }, lookup?: Lookup): CtFetch {
  return async (domain) => {
    try {
      const response = await httpsGet({
        host: CT_PROVIDER.host,
        path: ctPath(domain),
        timeoutMs: CT_LIMITS.timeoutMs,
        headers: { accept: "application/json", "user-agent": "GarnetOps-Exposure-CT/1" },
        ...(test ? { test } : {}),
        ...(lookup ? { lookup } : {}),
      });
      const body = await readCapped(response, CT_LIMITS.maxBytes);
      return parseCtNames(body.toString("utf8"), domain);
    } catch (error) {
      if (error instanceof CtError) throw error;
      if (error instanceof OutboundError) {
        if (error.code === "timeout") throw new CtError("timeout");
        if (error.code === "tooLarge") throw new CtError("tooLarge");
        if (error.code === "refusedAddress") throw new CtError("refusedAddress");
        if (error.code === "httpStatus" || error.code === "redirected") throw new CtError("httpStatus");
      }
      throw new CtError("unreachable");
    }
  };
}
