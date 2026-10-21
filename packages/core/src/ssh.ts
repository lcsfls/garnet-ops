/**
 * SSH deploy keys and pinned host keys (Node only).
 *
 * Deploy keys are Ed25519: every forge accepts them and they are short enough
 * to paste. SSH has no post-quantum signature that forges support yet; the
 * session itself is protected by the hybrid key exchange the worker prefers
 * (mlkem768x25519-sha256, sntrup761x25519-sha512), see apps/worker/src/git.ts.
 */
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";

export interface DeployKey {
  /** One line in OpenSSH `authorized_keys` format, to paste into the forge. */
  publicKey: string;
  /** Unencrypted OpenSSH private key (PEM armoured). Seal it immediately; never log it. */
  privateKey: string;
}

function sshString(data: Buffer | string): Buffer {
  const body = typeof data === "string" ? Buffer.from(data, "utf8") : data;
  const length = Buffer.alloc(4);
  length.writeUInt32BE(body.length);
  return Buffer.concat([length, body]);
}

function uint32(value: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(value);
  return b;
}

/** Generates an Ed25519 deploy key. The comment ends up in the forge's key list. */
export function generateDeployKey(comment: string): DeployKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = privateKey.export({ format: "jwk" });
  if (!jwk.d || !jwk.x) throw new Error("Ed25519 key export failed");
  const seed = Buffer.from(jwk.d, "base64url");
  const pub = Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url");
  const safeComment = comment.replace(/[^\w@.:-]/g, "-").slice(0, 100);

  const blob = Buffer.concat([sshString("ssh-ed25519"), sshString(pub)]);

  // openssh-key-v1, unencrypted (PROTOCOL.key in the OpenSSH sources).
  const check = randomBytes(4);
  let secret = Buffer.concat([
    check,
    check,
    sshString("ssh-ed25519"),
    sshString(pub),
    sshString(Buffer.concat([seed, pub])),
    sshString(safeComment),
  ]);
  const padding = (8 - (secret.length % 8)) % 8;
  secret = Buffer.concat([secret, Buffer.from(Array.from({ length: padding }, (_, i) => i + 1))]);
  seed.fill(0);

  const body = Buffer.concat([
    Buffer.from("openssh-key-v1\0", "latin1"),
    sshString("none"),
    sshString("none"),
    sshString(""),
    uint32(1),
    sshString(blob),
    sshString(secret),
  ]);
  secret.fill(0);
  const base64 = body.toString("base64");
  body.fill(0);
  const lines = base64.match(/.{1,70}/g) ?? [];

  return {
    publicKey: `ssh-ed25519 ${blob.toString("base64")} ${safeComment}`,
    privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----\n${lines.join("\n")}\n-----END OPENSSH PRIVATE KEY-----\n`,
  };
}

/** One host key from a known_hosts file, as ssh(1) writes it with HashKnownHosts=no. */
export interface KnownHost {
  /** `host` or `[host]:port`. */
  host: string;
  type: string;
  /** Base64 key blob. */
  key: string;
}

const KNOWN_HOST_LINE = /^(\[?[A-Za-z0-9.-]+\]?(?::[0-9]{1,5})?) ([a-z0-9@.-]{3,60}) ([A-Za-z0-9+/]+={0,2})$/;

/**
 * Parses known_hosts content strictly. Anything else (markers, hashed hosts,
 * options, comments) is rejected, so only plain, inspectable entries are pinned.
 */
export function parseKnownHosts(content: string): KnownHost[] | null {
  const lines = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  if (lines.length === 0 || lines.length > 10 || content.length > 8192) return null;
  const hosts: KnownHost[] = [];
  for (const line of lines) {
    const m = KNOWN_HOST_LINE.exec(line);
    if (!m) return null;
    hosts.push({ host: m[1] as string, type: m[2] as string, key: m[3] as string });
  }
  return hosts;
}

/** The fingerprint ssh(1) shows for a key: `SHA256:` plus unpadded base64. */
export function fingerprint(keyBase64: string): string {
  return `SHA256:${createHash("sha256").update(Buffer.from(keyBase64, "base64")).digest("base64").replace(/=+$/, "")}`;
}
