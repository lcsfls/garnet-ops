/**
 * Secrets vault: envelope encryption with sealed data keys (ADR 0004).
 *
 * Every secret gets its own random 256-bit data key and is encrypted with
 * AES-256-GCM. The data key is then sealed for the vault key with a hybrid,
 * post-quantum KEM: an ephemeral X25519 agreement and an ML-KEM-1024
 * encapsulation. Both shared secrets go into HKDF-SHA-256, so the wrapping key
 * stays secret as long as either X25519 or ML-KEM holds. This protects stored
 * secrets against "store now, decrypt later" with a future quantum computer.
 *
 * Anyone holding the vault public key can seal (the API); only the holder of
 * the vault private key can open (the worker).
 *
 * Both layers authenticate the same associated data, which binds a sealed
 * secret to its organisation, record and purpose. A ciphertext copied to
 * another row, tenant or purpose fails to open.
 *
 * Key files are PEM with two blocks: an X25519 key and an ML-KEM-1024 key
 * (SPKI for the public file, PKCS#8 for the private file).
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  decapsulate,
  diffieHellman,
  encapsulate,
  generateKeyPairSync,
  hkdfSync,
  type KeyObject,
  randomBytes,
} from "node:crypto";
import { z } from "zod";

const VERSION = 2;
const WRAP_INFO = Buffer.from("garnetops/vault/v2/wrap");
const KID_LABEL = Buffer.from("garnetops/vault/v2/kid");
const KEM = "ml-kem-1024";

export type SecretPurpose =
  | "forge-token"
  | "ssh-private-key"
  | "ai-api-key"
  | "netbird-token"
  | "smtp-password";

export interface SecretBinding {
  organizationId: string;
  recordId: string;
  purpose: SecretPurpose;
}

export interface VaultPublicKey {
  /** Stable identifier of the vault key, stored with every sealed secret for rotation. */
  id: string;
  /** Raw X25519 public key followed by the ML-KEM SPKI encoding; bound into every wrapping key. */
  recipient: Buffer;
  x25519: KeyObject;
  mlkem: KeyObject;
}

/** Same shape; `x25519` and `mlkem` hold the private keys. */
export interface VaultPrivateKey extends VaultPublicKey {}

const sealedSchema = z.object({
  v: z.literal(VERSION),
  kid: z.string().min(1),
  /** Ephemeral X25519 public key. */
  epk: z.string().min(1),
  /** ML-KEM ciphertext. */
  kem: z.string().min(1),
  wn: z.string().min(1),
  wk: z.string().min(1),
  dn: z.string().min(1),
  ct: z.string(),
});

/** The stored form of a sealed secret. Opaque to everything except this module. */
export type SealedSecret = z.infer<typeof sealedSchema>;

const b64 = (buf: Buffer) => buf.toString("base64url");
const unb64 = (s: string) => Buffer.from(s, "base64url");

function aadFor(binding: SecretBinding): Buffer {
  for (const part of [binding.organizationId, binding.recordId, binding.purpose]) {
    if (!part || part.includes("|")) throw new Error("Invalid secret binding");
  }
  return Buffer.from(`${binding.organizationId}|${binding.recordId}|${binding.purpose}`, "utf8");
}

function rawX25519(key: KeyObject): Buffer {
  const jwk = key.export({ format: "jwk" });
  if (!jwk.x) throw new Error("Not an X25519 key");
  return unb64(jwk.x);
}

function gcmEncrypt(key: Buffer, nonce: Buffer, plaintext: Buffer, aad: Buffer): Buffer {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([ct, cipher.getAuthTag()]);
}

function gcmDecrypt(key: Buffer, nonce: Buffer, sealed: Buffer, aad: Buffer): Buffer {
  if (sealed.length < 16) throw new Error("Ciphertext too short");
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(sealed.subarray(sealed.length - 16));
  return Buffer.concat([decipher.update(sealed.subarray(0, sealed.length - 16)), decipher.final()]);
}

/**
 * Combines both shared secrets. The salt is a hash over every public value of
 * the exchange (ephemeral key, KEM ciphertext, recipient keys), so a wrapping
 * key is tied to exactly this exchange and this vault key.
 */
function wrapKey(
  kemShared: Buffer,
  dhShared: Buffer,
  epkRaw: Buffer,
  kemCt: Buffer,
  recipient: Buffer,
): Buffer {
  const salt = createHash("sha256").update(epkRaw).update(kemCt).update(recipient).digest();
  const ikm = Buffer.concat([kemShared, dhShared]);
  try {
    return Buffer.from(hkdfSync("sha256", ikm, salt, WRAP_INFO, 32));
  } finally {
    ikm.fill(0);
  }
}

/** Seals a secret for the vault key. Callable with the public key only. */
export function seal(
  plaintext: string | Buffer,
  binding: SecretBinding,
  vault: VaultPublicKey,
): SealedSecret {
  const aad = aadFor(binding);
  const data = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : Buffer.from(plaintext);
  const dek = randomBytes(32);
  const dataNonce = randomBytes(12);
  const wrapNonce = randomBytes(12);
  const ephemeral = generateKeyPairSync("x25519");
  const epkRaw = rawX25519(ephemeral.publicKey);
  const dhShared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: vault.x25519 });
  const { sharedKey: kemShared, ciphertext: kemCt } = encapsulate(vault.mlkem);
  const kek = wrapKey(kemShared, dhShared, epkRaw, kemCt, vault.recipient);
  try {
    const ct = gcmEncrypt(dek, dataNonce, data, aad);
    const wrapped = gcmEncrypt(kek, wrapNonce, dek, Buffer.concat([Buffer.from("wrap|"), aad]));
    return {
      v: VERSION,
      kid: vault.id,
      epk: b64(epkRaw),
      kem: b64(kemCt),
      wn: b64(wrapNonce),
      wk: b64(wrapped),
      dn: b64(dataNonce),
      ct: b64(ct),
    };
  } finally {
    dek.fill(0);
    dhShared.fill(0);
    kemShared.fill(0);
    kek.fill(0);
    if (typeof plaintext !== "string") data.fill(0);
  }
}

/**
 * Opens a sealed secret. Only the worker holds the vault private key.
 * The caller must zero the returned buffer when done with it.
 */
export function open(sealed: unknown, binding: SecretBinding, vault: VaultPrivateKey): Buffer {
  const record = sealedSchema.parse(sealed);
  if (record.kid !== vault.id) throw new Error(`Sealed with vault key ${record.kid}, not ${vault.id}`);
  const aad = aadFor(binding);
  const epkRaw = unb64(record.epk);
  const kemCt = unb64(record.kem);
  const ephemeralPublic = createPublicKey({
    key: { kty: "OKP", crv: "X25519", x: record.epk },
    format: "jwk",
  });
  const dhShared = diffieHellman({ privateKey: vault.x25519, publicKey: ephemeralPublic });
  // A tampered KEM ciphertext yields a different (implicit-rejection) secret, so the GCM check below fails.
  const kemShared = decapsulate(vault.mlkem, kemCt);
  const kek = wrapKey(kemShared, dhShared, epkRaw, kemCt, vault.recipient);
  let dek: Buffer | undefined;
  try {
    dek = gcmDecrypt(kek, unb64(record.wn), unb64(record.wk), Buffer.concat([Buffer.from("wrap|"), aad]));
    return gcmDecrypt(dek, unb64(record.dn), unb64(record.ct), aad);
  } finally {
    dhShared.fill(0);
    kemShared.fill(0);
    kek.fill(0);
    dek?.fill(0);
  }
}

function recipientOf(x25519Public: KeyObject, mlkemPublic: KeyObject): Buffer {
  return Buffer.concat([rawX25519(x25519Public), mlkemPublic.export({ type: "spki", format: "der" })]);
}

/** Derives a short, stable key ID from both public keys (first 16 hex chars of a SHA-256). */
function keyIdOf(recipient: Buffer): string {
  return createHash("sha256").update(KID_LABEL).update(recipient).digest("hex").slice(0, 16);
}

function pemBlocks(pem: string): string[] {
  return pem.match(/-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----/g) ?? [];
}

/** Picks exactly one X25519 and one ML-KEM-1024 key from the parsed PEM blocks. */
function pickKeys(keys: KeyObject[], kind: string): { x25519: KeyObject; mlkem: KeyObject } {
  const x25519 = keys.filter((k) => k.asymmetricKeyType === "x25519");
  const mlkem = keys.filter((k) => k.asymmetricKeyType === KEM);
  if (keys.length !== 2 || x25519.length !== 1 || mlkem.length !== 1) {
    throw new Error(`Vault ${kind} key file must contain one X25519 and one ML-KEM-1024 key`);
  }
  return { x25519: x25519[0] as KeyObject, mlkem: mlkem[0] as KeyObject };
}

/** Generates a new vault key pair as PEM strings (for `garnetops vault init`). */
export function generateVaultKeyPair(): { publicKeyPem: string; privateKeyPem: string; id: string } {
  const x = generateKeyPairSync("x25519");
  const k = generateKeyPairSync(KEM);
  const pem = (key: KeyObject, type: "spki" | "pkcs8") => key.export({ type, format: "pem" }).toString();
  return {
    publicKeyPem: pem(x.publicKey, "spki") + pem(k.publicKey, "spki"),
    privateKeyPem: pem(x.privateKey, "pkcs8") + pem(k.privateKey, "pkcs8"),
    id: keyIdOf(recipientOf(x.publicKey, k.publicKey)),
  };
}

export function loadVaultPublicKey(pem: string): VaultPublicKey {
  const { x25519, mlkem } = pickKeys(
    pemBlocks(pem).map((block) => createPublicKey(block)),
    "public",
  );
  const recipient = recipientOf(x25519, mlkem);
  return { id: keyIdOf(recipient), recipient, x25519, mlkem };
}

export function loadVaultPrivateKey(pem: string): VaultPrivateKey {
  const { x25519, mlkem } = pickKeys(
    pemBlocks(pem).map((block) => createPrivateKey(block)),
    "private",
  );
  const recipient = recipientOf(createPublicKey(x25519), createPublicKey(mlkem));
  return { id: keyIdOf(recipient), recipient, x25519, mlkem };
}
