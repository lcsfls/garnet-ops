/**
 * The host agent (ADR 0034): what the agent and the API agree on. The signature of a request, the shape and limits of what an
 * agent may report, how an image is linked to a repository, and how image references and version tags are read. Everything an
 * agent sends is hostile input: the schemas cut and clean it before anything is stored.
 */
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from "node:crypto";
import { z } from "zod";
import { stripControl } from "./fix-prs.ts";

/* -------------------------------------------------------------------------- */
/* Enrolment                                                                   */
/* -------------------------------------------------------------------------- */

export const ENROLMENT_PREFIX = "goe_";
/** How long an enrolment code can be used, and for how many hosts (one). */
export const ENROLMENT_TTL_MS = 24 * 3600_000;

/** A new enrolment code: 256 random bits. Only its hash is stored. */
export function newEnrolmentCode(): string {
  return `${ENROLMENT_PREFIX}${randomBytes(32).toString("base64url")}`;
}

export const enrolmentCodeSchema = z.string().regex(/^goe_[A-Za-z0-9_-]{43}$/);

/** The stored form of an enrolment code. */
export const hashEnrolmentCode = (code: string): string => createHash("sha256").update(code).digest("hex");

/* -------------------------------------------------------------------------- */
/* Signed requests                                                             */
/* -------------------------------------------------------------------------- */

export const AGENT_AUTH_SCHEME = "GarnetOps-Agent";
/** A request older or newer than this is refused; a nonce is remembered twice as long. */
export const SIGNATURE_WINDOW_MS = 5 * 60_000;
export const NONCE_TTL_MS = 2 * SIGNATURE_WINDOW_MS;
/** The largest body an agent may send. */
export const MAX_AGENT_BODY_BYTES = 8 * 1024 * 1024;

/** A key pair for a new host: the public key as base64url of its 32 raw bytes, the private key as PKCS#8 PEM. */
export function newAgentKeyPair(): { publicKey: string; privateKeyPem: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" });
  return {
    publicKey: Buffer.from(der.subarray(der.length - 32)).toString("base64url"),
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
  };
}

export const publicKeySchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);

/** The SPKI prefix of an Ed25519 public key; the 32 raw bytes follow it. */
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function publicKeyObject(raw: string) {
  const bytes = Buffer.from(raw, "base64url");
  if (bytes.length !== 32) throw new Error("bad public key");
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, bytes]), format: "der", type: "spki" });
}

/** What is signed: the method, the path with its query, the time, the nonce and the SHA-256 of the body, one per line. */
export function signingInput(input: {
  method: string;
  path: string;
  timestamp: number;
  nonce: string;
  body: string | Uint8Array;
}): Buffer {
  const bodyHash = createHash("sha256").update(input.body).digest("hex");
  return Buffer.from(
    [input.method.toUpperCase(), input.path, String(input.timestamp), input.nonce, bodyHash].join("\n"),
  );
}

export interface SignedHeader {
  hostId: string;
  timestamp: number;
  nonce: string;
  signature: string;
}

/** The Authorization header of a signed request. */
export function signRequest(input: {
  hostId: string;
  privateKeyPem: string;
  method: string;
  path: string;
  body: string | Uint8Array;
  now?: number;
}): string {
  const timestamp = input.now ?? Date.now();
  const nonce = randomBytes(16).toString("base64url");
  const signature = sign(null, signingInput({ ...input, timestamp, nonce }), input.privateKeyPem).toString(
    "base64url",
  );
  return `${AGENT_AUTH_SCHEME} host="${input.hostId}", ts="${timestamp}", nonce="${nonce}", sig="${signature}"`;
}

const HEADER =
  /^GarnetOps-Agent host="(hst_[A-Za-z0-9_-]{1,64})", ts="(\d{13})", nonce="([A-Za-z0-9_-]{22})", sig="([A-Za-z0-9_-]{86})"$/;

/** The parts of an Authorization header, or null if it is not one of ours. */
export function parseSignedHeader(value: string | undefined | null): SignedHeader | null {
  const m = HEADER.exec(value ?? "");
  if (!m) return null;
  return {
    hostId: m[1] as string,
    timestamp: Number(m[2]),
    nonce: m[3] as string,
    signature: m[4] as string,
  };
}

/** Whether `signature` is the host's signature of this request. Never throws. */
export function verifySignature(input: {
  publicKey: string;
  method: string;
  path: string;
  timestamp: number;
  nonce: string;
  body: string | Uint8Array;
  signature: string;
}): boolean {
  try {
    return verify(
      null,
      signingInput(input),
      publicKeyObject(input.publicKey),
      Buffer.from(input.signature, "base64url"),
    );
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* What an agent reports                                                       */
/* -------------------------------------------------------------------------- */

/** Text from a host: one line, no control or invisible characters, cut. */
const text = (max: number) =>
  z
    .string()
    .max(max * 4)
    .transform((v) => stripControl(v).slice(0, max));
const optionalText = (max: number) =>
  z
    .string()
    .max(max * 4)
    .nullish()
    .transform((v) => (v ? stripControl(v).slice(0, max) || null : null));

/** A Docker id: 64 hex characters, with or without "sha256:". */
const dockerId = z
  .string()
  .regex(/^(sha256:)?[a-f0-9]{64}$/)
  .transform((v) => v.replace(/^sha256:/, ""));

/** The only labels kept; everything else an image carries is dropped. */
export const KEPT_LABELS = [
  "org.opencontainers.image.source",
  "org.opencontainers.image.revision",
  "org.opencontainers.image.version",
  "org.opencontainers.image.title",
  "org.opencontainers.image.created",
] as const;

const labels = z
  .record(z.string().max(200), z.string().max(4000))
  .nullish()
  .transform((all) => {
    const kept: Partial<Record<(typeof KEPT_LABELS)[number], string>> = {};
    for (const key of KEPT_LABELS) {
      const value = all?.[key];
      if (typeof value === "string" && value.trim()) kept[key] = stripControl(value).slice(0, 500);
    }
    return kept;
  });

export const MAX_CONTAINERS = 1000;
export const MAX_IMAGES = 500;
export const MAX_PACKAGES = 50_000;

export const enrolBodySchema = z.object({
  code: enrolmentCodeSchema,
  publicKey: publicKeySchema,
  hostname: text(253),
  agentVersion: text(40),
});
export type EnrolBody = z.infer<typeof enrolBodySchema>;

export const inventorySchema = z.object({
  hostname: text(253),
  agentVersion: text(40),
  dockerVersion: optionalText(40),
  os: optionalText(80),
  containers: z
    .array(
      z.object({
        id: dockerId,
        name: text(200),
        image: text(500),
        imageId: dockerId,
        state: text(40),
        startedAt: z.string().datetime({ offset: true }).nullish(),
      }),
    )
    .max(MAX_CONTAINERS),
  images: z
    .array(
      z.object({
        id: dockerId,
        tags: z.array(text(500)).max(50).default([]),
        digests: z.array(text(600)).max(50).default([]),
        os: optionalText(40),
        architecture: optionalText(40),
        created: z.string().datetime({ offset: true }).nullish(),
        labels,
      }),
    )
    .max(MAX_IMAGES),
});
export type Inventory = z.infer<typeof inventorySchema>;

export const packagesSchema = z.object({
  imageId: dockerId,
  /** The distribution syft saw ("debian 12"), shown as text. */
  distro: optionalText(80),
  packages: z
    .array(
      z.object({
        name: text(300),
        version: text(200),
        type: text(50),
        purl: z
          .string()
          .max(2000)
          .refine((v) => v.startsWith("pkg:"))
          .transform((v) => stripControl(v).slice(0, 1000)),
      }),
    )
    .max(MAX_PACKAGES),
});
export type ImagePackages = z.infer<typeof packagesSchema>;

/* -------------------------------------------------------------------------- */
/* Linking an image to a repository                                            */
/* -------------------------------------------------------------------------- */

/**
 * The address of a repository as a key both a repository URL and an image's `org.opencontainers.image.source` label reduce to:
 * the host name (no port, no user), the path in lower case, without ".git" and slashes at the ends. Null for anything else.
 */
export function sourceKey(value: string | null | undefined): string | null {
  if (!value) return null;
  const raw = value.trim();
  let host: string;
  let path: string;
  const scp = /^(?:[^@/\s]+@)?([A-Za-z0-9.-]+):(?!\/\/)([^\s]+)$/.exec(raw);
  if (/^(https?|ssh|git):\/\//i.test(raw)) {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      return null;
    }
    host = url.hostname;
    path = url.pathname;
  } else if (scp) {
    host = scp[1] as string;
    path = scp[2] as string;
  } else {
    return null;
  }
  const segments = path
    .replace(/\.git\/*$/i, "")
    .split("/")
    .filter(Boolean);
  if (!host || segments.length < 2 || segments.some((s) => !/^[A-Za-z0-9_.~-]{1,100}$/.test(s))) return null;
  return `${host}/${segments.join("/")}`.toLowerCase().slice(0, 300);
}

/* -------------------------------------------------------------------------- */
/* Image references and version tags                                           */
/* -------------------------------------------------------------------------- */

export interface ImageRef {
  /** The registry host, "docker.io" for Docker Hub. */
  registry: string;
  /** The repository in the registry, "library/nginx" for official Docker Hub images. */
  repository: string;
  tag: string | null;
  digest: string | null;
}

/** Reads `nginx`, `nginx:1.27`, `ghcr.io/owner/app:v2@sha256:...`. Null for anything that is not a reference. */
export function parseImageRef(value: string): ImageRef | null {
  const ref = value.trim();
  if (!ref || ref.length > 500 || /\s/.test(ref)) return null;
  let rest = ref;
  let digest: string | null = null;
  const at = rest.indexOf("@");
  if (at >= 0) {
    digest = rest.slice(at + 1);
    rest = rest.slice(0, at);
    if (!/^sha256:[a-f0-9]{64}$/.test(digest)) return null;
  }
  let tag: string | null = null;
  const lastSlash = rest.lastIndexOf("/");
  const colon = rest.lastIndexOf(":");
  if (colon > lastSlash) {
    tag = rest.slice(colon + 1);
    rest = rest.slice(0, colon);
    if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(tag)) return null;
  }
  const parts = rest.split("/");
  let registry = "docker.io";
  const first = parts[0] as string;
  if (parts.length > 1 && (first.includes(".") || first.includes(":") || first === "localhost")) {
    registry = first.toLowerCase();
    parts.shift();
  }
  if (registry === "index.docker.io" || registry === "registry-1.docker.io") registry = "docker.io";
  if (registry === "docker.io" && parts.length === 1) parts.unshift("library");
  const repository = parts.join("/");
  if (!/^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/.test(repository)) return null;
  return { registry, repository, tag: tag ?? (digest ? null : "latest"), digest };
}

/** A version tag: an optional "v", two to four numbers, an optional suffix such as "-alpine". */
export interface VersionTag {
  prefix: string;
  numbers: number[];
  suffix: string;
}

export function parseVersionTag(tag: string): VersionTag | null {
  const m = /^(v?)(\d{1,6}(?:\.\d{1,6}){1,3})(-[A-Za-z][A-Za-z0-9.-]{0,40})?$/.exec(tag);
  if (!m) return null;
  return { prefix: m[1] as string, numbers: (m[2] as string).split(".").map(Number), suffix: m[3] ?? "" };
}

function compareNumbers(a: number[], b: number[]): number {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const d = (a[i] ?? 0) - (b[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export type UpdateKind = "major" | "minor" | "patch";

/**
 * The newest tag of the same shape (same prefix, same count of numbers, same suffix) that is newer than `current`, and whether it is
 * a major, minor or patch step. Pre-releases ("-rc1", "-beta") are only compared with tags of the same suffix, so a stable tag never
 * suggests a release candidate.
 */
export function newerTag(current: string, tags: readonly string[]): { tag: string; kind: UpdateKind } | null {
  const now = parseVersionTag(current);
  if (!now) return null;
  let best: { tag: string; v: VersionTag } | null = null;
  for (const tag of tags) {
    const v = parseVersionTag(tag);
    if (!v || v.prefix !== now.prefix || v.suffix !== now.suffix || v.numbers.length !== now.numbers.length)
      continue;
    if (compareNumbers(v.numbers, now.numbers) <= 0) continue;
    if (!best || compareNumbers(v.numbers, best.v.numbers) > 0) best = { tag, v };
  }
  if (!best) return null;
  const kind: UpdateKind =
    best.v.numbers[0] !== now.numbers[0]
      ? "major"
      : now.numbers.length > 2 && best.v.numbers[1] === now.numbers[1]
        ? "patch"
        : "minor";
  return { tag: best.tag, kind };
}

/** The key a registry check is stored under: `registry/repository:tag`, or null for a reference without a tag. */
export function imageRefKey(value: string): string | null {
  const ref = parseImageRef(value);
  return ref?.tag ? `${ref.registry}/${ref.repository}:${ref.tag}` : null;
}
