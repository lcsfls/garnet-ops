import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  generateVaultKeyPair,
  loadVaultPrivateKey,
  loadVaultPublicKey,
  open,
  seal,
  vaultPublicKeyOf,
} from "./vault.ts";

const pair = generateVaultKeyPair();
const pub = loadVaultPublicKey(pair.publicKeyPem);
const priv = loadVaultPrivateKey(pair.privateKeyPem);
const binding = { organizationId: "org_1", recordId: "rec_1", purpose: "forge-token" } as const;

describe("vault", () => {
  it("round-trips a secret", () => {
    const sealed = seal("ghp_example-token", binding, pub);
    expect(open(sealed, binding, priv).toString("utf8")).toBe("ghp_example-token");
  });

  it("lets the holder of the private key seal for itself", () => {
    const own = vaultPublicKeyOf(priv);
    expect(own.id).toBe(priv.id);
    const sealed = seal("worker-generated-secret", { ...binding, purpose: "ldap-user-password" }, own);
    expect(open(sealed, { ...binding, purpose: "ldap-user-password" }, priv).toString("utf8")).toBe(
      "worker-generated-secret",
    );
  });

  it("uses the same key ID on both halves", () => {
    expect(pub.id).toBe(priv.id);
    expect(pub.id).toBe(pair.id);
  });

  it("never contains the plaintext", () => {
    const sealed = seal("super-secret-value", binding, pub);
    expect(JSON.stringify(sealed)).not.toContain("super-secret-value");
  });

  it("produces a different ciphertext every time", () => {
    expect(seal("x", binding, pub).ct).not.toBe(seal("x", binding, pub).ct);
  });

  it("fails when moved to another record, tenant or purpose", () => {
    const sealed = seal("token", binding, pub);
    expect(() => open(sealed, { ...binding, recordId: "rec_2" }, priv)).toThrow();
    expect(() => open(sealed, { ...binding, organizationId: "org_2" }, priv)).toThrow();
    expect(() => open(sealed, { ...binding, purpose: "ssh-private-key" }, priv)).toThrow();
  });

  it("fails when any field is tampered with", () => {
    const sealed = seal("token", binding, pub);
    for (const field of ["wk", "ct", "dn", "wn", "epk", "kem"] as const) {
      const raw = Buffer.from(sealed[field], "base64url");
      raw[0] = (raw[0] ?? 0) ^ 1;
      expect(() => open({ ...sealed, [field]: raw.toString("base64url") }, binding, priv)).toThrow();
    }
  });

  it("fails with another vault key", () => {
    const other = generateVaultKeyPair();
    const sealed = seal("token", binding, pub);
    expect(() => open(sealed, binding, loadVaultPrivateKey(other.privateKeyPem))).toThrow();
  });

  it("seals with both X25519 and ML-KEM-1024", () => {
    const sealed = seal("token", binding, pub);
    expect(sealed.v).toBe(2);
    expect(Buffer.from(sealed.epk, "base64url")).toHaveLength(32);
    expect(Buffer.from(sealed.kem, "base64url")).toHaveLength(1568); // ML-KEM-1024 ciphertext size
  });

  it("needs both halves of the private key", () => {
    // Same X25519 key, different ML-KEM key: the wrapping key differs, so opening fails.
    const sealed = seal("token", binding, pub);
    const xOnly = pair.privateKeyPem.match(
      /-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/,
    )?.[0];
    const otherKem = generateKeyPairSync("ml-kem-1024").privateKey.export({ type: "pkcs8", format: "pem" });
    const mixed = loadVaultPrivateKey(`${xOnly}\n${otherKem}`);
    expect(() => open(sealed, binding, { ...mixed, id: priv.id, recipient: priv.recipient })).toThrow();
  });

  it("refuses key files without the post-quantum half", () => {
    const xOnly = generateKeyPairSync("x25519").publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(() => loadVaultPublicKey(xOnly)).toThrow(/ML-KEM-1024/);
    expect(() => loadVaultPublicKey(xOnly + xOnly)).toThrow(/ML-KEM-1024/);
  });

  it("rejects bindings that could collide", () => {
    expect(() => seal("x", { ...binding, recordId: "a|b" }, pub)).toThrow();
    expect(() => seal("x", { ...binding, recordId: "" }, pub)).toThrow();
  });
});
