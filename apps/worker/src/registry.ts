/**
 * Asking a public container registry about an image reference (ADR 0034, opt-in): the digest a tag points to now, and the tags of
 * the repository. Without credentials: a registry that wants them answers 401 with its token service, which issues an anonymous pull
 * token for public images. Every request goes through the address-checked client (public addresses only, HTTPS on port 443, TLS 1.2+,
 * no redirects, a size cap); the token service is followed only on HTTPS. Answers are hostile: schema-checked and cut.
 */
import type { IncomingHttpHeaders } from "node:http";
import { z } from "zod";
import { httpsGet, type Lookup, OutboundError, readCapped } from "./outbound.ts";

export const REGISTRY_LIMITS = {
  /** Per answer. */
  maxBytes: 4 * 1024 * 1024,
  timeoutMs: 20_000,
  /** Tags read per repository (pages of 1000). */
  maxTags: 10_000,
};

export type RegistryErrorCode =
  | "unsupported"
  | "unauthorized"
  | "notFound"
  | "rateLimited"
  | "unreachable"
  | "invalidResponse";

export class RegistryError extends Error {
  readonly code: RegistryErrorCode;
  constructor(code: RegistryErrorCode) {
    super(code);
    this.name = "RegistryError";
    this.code = code;
  }
}

/** Tests only: reach a local registry instead of the internet. */
export interface RegistryTestHooks {
  lookup?: Lookup;
  ca?: string;
  port?: number;
}

const MANIFEST_TYPES = [
  "application/vnd.oci.image.index.v1+json",
  "application/vnd.docker.distribution.manifest.list.v2+json",
  "application/vnd.oci.image.manifest.v1+json",
  "application/vnd.docker.distribution.manifest.v2+json",
].join(", ");

/** The host to talk to for a registry name, or null if it is not one we may ask (a port other than 443, an address). */
export function registryHost(registry: string): string | null {
  if (registry === "docker.io") return "registry-1.docker.io";
  const [name, port] = registry.split(":");
  if (port && port !== "443") return null;
  if (!name || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(name)) return null;
  return name;
}

/** `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="..."` */
export function parseChallenge(
  header: string | string[] | undefined,
): { realm: URL; service: string | null } | null {
  const value = Array.isArray(header) ? header[0] : header;
  if (!value || !/^Bearer\s/i.test(value)) return null;
  const params = new Map<string, string>();
  for (const m of value.matchAll(/(\w+)="([^"]*)"/g))
    params.set((m[1] as string).toLowerCase(), m[2] as string);
  const realm = params.get("realm");
  if (!realm) return null;
  let url: URL;
  try {
    url = new URL(realm);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username || url.password || (url.port && url.port !== "443"))
    return null;
  return { realm: url, service: params.get("service") ?? null };
}

const tokenSchema = z.object({
  token: z.string().max(16_000).optional(),
  access_token: z.string().max(16_000).optional(),
});
const tagsSchema = z.object({ tags: z.array(z.string().max(200)).nullable().optional() });

export class RegistryClient {
  /** Tokens per registry and repository, for the run of one check. */
  private readonly tokens = new Map<string, string>();

  private readonly test: RegistryTestHooks | undefined;

  constructor(test?: RegistryTestHooks) {
    this.test = test;
  }

  private async get(
    host: string,
    path: string,
    headers: Record<string, string>,
    method: "GET" | "HEAD" = "GET",
  ): Promise<{ headers: IncomingHttpHeaders; body: Buffer }> {
    const res = await httpsGet({
      host,
      path,
      method,
      headers,
      timeoutMs: REGISTRY_LIMITS.timeoutMs,
      ...(this.test ? { test: this.test } : {}),
    });
    const body = method === "HEAD" ? Buffer.alloc(0) : await readCapped(res, REGISTRY_LIMITS.maxBytes);
    if (method === "HEAD") res.close();
    return { headers: res.headers, body };
  }

  /** A request to the registry with an anonymous token if it asks for one. */
  private async call(
    registry: string,
    repository: string,
    path: string,
    headers: Record<string, string>,
    method: "GET" | "HEAD" = "GET",
  ) {
    const host = registryHost(registry);
    if (!host) throw new RegistryError("unsupported");
    const key = `${host}/${repository}`;
    const withToken = () => {
      const token = this.tokens.get(key);
      return token ? { ...headers, authorization: `Bearer ${token}` } : headers;
    };
    try {
      return await this.get(host, path, withToken(), method);
    } catch (error) {
      if (!(error instanceof OutboundError)) throw error;
      if (error.code === "httpStatus" && error.status === 401 && !this.tokens.has(key)) {
        const challenge = parseChallenge(error.headers?.["www-authenticate"]);
        if (!challenge) throw new RegistryError("unauthorized");
        await this.fetchToken(challenge, repository, key);
        try {
          return await this.get(host, path, withToken(), method);
        } catch (again) {
          throw this.mapError(again);
        }
      }
      throw this.mapError(error);
    }
  }

  private async fetchToken(
    challenge: { realm: URL; service: string | null },
    repository: string,
    key: string,
  ) {
    const url = new URL(challenge.realm);
    if (challenge.service) url.searchParams.set("service", challenge.service);
    url.searchParams.set("scope", `repository:${repository}:pull`);
    let body: Buffer;
    try {
      ({ body } = await this.get(url.hostname, `${url.pathname}${url.search}`, {
        accept: "application/json",
      }));
    } catch (error) {
      throw this.mapError(error);
    }
    const parsed = tokenSchema.safeParse(JSON.parse(body.toString("utf8") || "{}"));
    const token = parsed.success ? (parsed.data.token ?? parsed.data.access_token) : undefined;
    if (!token) throw new RegistryError("unauthorized");
    this.tokens.set(key, token);
  }

  private mapError(error: unknown): RegistryError {
    if (error instanceof RegistryError) return error;
    if (error instanceof OutboundError) {
      if (error.status === 401 || error.status === 403) return new RegistryError("unauthorized");
      if (error.status === 404) return new RegistryError("notFound");
      if (error.status === 429) return new RegistryError("rateLimited");
      if (error.code === "tooLarge") return new RegistryError("invalidResponse");
      return new RegistryError("unreachable");
    }
    if (error instanceof SyntaxError) return new RegistryError("invalidResponse");
    return new RegistryError("unreachable");
  }

  /** The digest the tag points to now (HEAD of the manifest, which Docker Hub does not count as a pull). */
  async digest(registry: string, repository: string, tag: string): Promise<string | null> {
    const res = await this.call(
      registry,
      repository,
      `/v2/${repository}/manifests/${encodeURIComponent(tag)}`,
      { accept: MANIFEST_TYPES },
      "HEAD",
    );
    const digest = res.headers["docker-content-digest"];
    const value = Array.isArray(digest) ? digest[0] : digest;
    return value && /^sha256:[a-f0-9]{64}$/.test(value) ? value : null;
  }

  /** The tags of a repository, at most `maxTags`, following the registry's `Link` pages on the same host. */
  async tags(registry: string, repository: string): Promise<string[]> {
    const all: string[] = [];
    let path: string | null = `/v2/${repository}/tags/list?n=1000`;
    while (path && all.length < REGISTRY_LIMITS.maxTags) {
      const res = await this.call(registry, repository, path, { accept: "application/json" });
      let json: unknown;
      try {
        json = JSON.parse(res.body.toString("utf8"));
      } catch {
        throw new RegistryError("invalidResponse");
      }
      const parsed = tagsSchema.safeParse(json);
      if (!parsed.success) throw new RegistryError("invalidResponse");
      all.push(...(parsed.data.tags ?? []).filter((t) => /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(t)));
      const link = res.headers.link;
      const next = (Array.isArray(link) ? link[0] : link)?.match(/^<([^>]+)>;\s*rel="next"/)?.[1];
      // Only a path on the same registry is followed.
      path = next?.startsWith(`/v2/${repository}/tags/list?`) ? next : null;
    }
    return all.slice(0, REGISTRY_LIMITS.maxTags);
  }
}
