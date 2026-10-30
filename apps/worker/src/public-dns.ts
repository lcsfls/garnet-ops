/**
 * The organisation's optional public DNS resolver (Settings → Modules): lookups of public names (website checks, the proof of
 * control, registry checks, Certificate Transparency) ask the local resolver and the chosen provider at the same time, and the first
 * clear answer counts. A slow local resolver then no longer holds up a check; names the local resolver alone knows are never asked
 * this way, because only public names are looked up here. Off by default: the names go to the provider.
 */
import type { LookupAddress } from "node:dns";
import { Resolver } from "node:dns/promises";
import {
  isPublicDnsProvider,
  PUBLIC_DNS_PROVIDERS,
  type PublicDnsProvider,
} from "@garnetops/core/public-dns";
import { schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { db } from "./db.ts";
import { type DnsLike, systemResolver } from "./exposure-net.ts";
import { type Lookup, lookupVia, systemAddresses } from "./outbound.ts";

/** The provider an organisation chose, or null. */
export async function publicDnsOf(organizationId: string): Promise<PublicDnsProvider | null> {
  const d = schema.publicDnsSettings;
  const [row] = await db
    .select({ provider: d.provider })
    .from(d)
    .where(eq(d.organizationId, organizationId))
    .limit(1);
  return isPublicDnsProvider(row?.provider) ? row.provider : null;
}

/** "The name has no such record": an answer, as clear as a record. Anything else (a time-out, SERVFAIL) is a failure to ask. */
const NO_SUCH = new Set(["ENODATA", "ENOTFOUND", "NODATA"]);
const codeOf = (error: unknown) => (error as NodeJS.ErrnoException | undefined)?.code ?? "";

/**
 * The first clear answer of two lookups: records, or "no such record". A failure waits for the other; when both fail, the local
 * resolver's error is the one reported.
 */
export function firstAnswer<T>(local: Promise<T>, extra: Promise<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    let pending = 2;
    let localError: unknown = null;
    const settle = (p: Promise<T>, isLocal: boolean) =>
      p.then(resolve, (error: unknown) => {
        if (NO_SUCH.has(codeOf(error))) return reject(error);
        if (isLocal) localError = error;
        if (--pending === 0) reject(localError ?? error);
      });
    settle(local, true);
    settle(extra, false);
  });
}

const METHODS = [
  "resolve4",
  "resolve6",
  "resolveCname",
  "resolveMx",
  "resolveNs",
  "resolveCaa",
  "resolveTxt",
  "reverse",
] as const satisfies readonly (keyof DnsLike)[];

/** A resolver that asks `local` and `extra` together for every query (see {@link firstAnswer}). */
export function racingResolver(local: DnsLike, extra: DnsLike): DnsLike {
  const out = {} as Record<(typeof METHODS)[number], (name: string) => Promise<unknown>>;
  for (const method of METHODS) {
    out[method] = (name: string) =>
      firstAnswer(
        (local[method] as (n: string) => Promise<unknown>)(name),
        (extra[method] as (n: string) => Promise<unknown>)(name),
      );
  }
  return out as unknown as DnsLike;
}

/** A resolver that asks only the provider's servers. */
export function providerResolver(provider: PublicDnsProvider): DnsLike {
  const resolver = new Resolver({ timeout: 2000, tries: 2 });
  resolver.setServers([...PUBLIC_DNS_PROVIDERS[provider].servers]);
  return resolver as unknown as DnsLike;
}

/** The resolver for website checks and the proof: the local one, and the provider's next to it if the organisation chose one. */
export function resolverFor(provider: PublicDnsProvider | null): DnsLike {
  return provider ? racingResolver(systemResolver(), providerResolver(provider)) : systemResolver();
}

/** The addresses of a name from a resolver: IPv4 and IPv6 together, "no such record" only when both have none. */
async function addressesFrom(dns: DnsLike, hostname: string): Promise<LookupAddress[]> {
  const [v4, v6] = await Promise.allSettled([dns.resolve4(hostname), dns.resolve6(hostname)]);
  const list: LookupAddress[] = [
    ...(v4.status === "fulfilled" ? v4.value.map((address) => ({ address, family: 4 })) : []),
    ...(v6.status === "fulfilled" ? v6.value.map((address) => ({ address, family: 6 })) : []),
  ];
  if (list.length > 0) return list;
  throw v4.status === "rejected" ? v4.reason : Object.assign(new Error("no address"), { code: "ENODATA" });
}

/**
 * The lookup for outgoing HTTPS to public services (registries, crt.sh) with the provider next to the local resolver. The address
 * policy of `lookupVia` applies to whichever answer comes first. `undefined` without a provider: the client's own lookup.
 */
export function lookupFor(provider: PublicDnsProvider | null, extra?: DnsLike): Lookup | undefined {
  if (!provider) return undefined;
  const dns = extra ?? providerResolver(provider);
  return lookupVia((hostname, options) =>
    firstAnswer(systemAddresses(hostname, options), addressesFrom(dns, hostname)),
  );
}
