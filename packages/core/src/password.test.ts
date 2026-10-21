import { argon2Sync, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { hashPassword, verifyPassword } from "./password.ts";

describe("password", () => {
  it("hashes with Argon2id in PHC format", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(hash).toMatch(/^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$/);
  });

  it("verifies the right password and rejects a wrong one", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(await verifyPassword(hash, "correct horse battery staple")).toBe(true);
    expect(await verifyPassword(hash, "correct horse battery stapler")).toBe(false);
  });

  it("uses a fresh salt every time", async () => {
    expect(await hashPassword("same")).not.toBe(await hashPassword("same"));
  });

  it("verifies hashes made with other, stored parameters", async () => {
    // As if made by an older release with the OWASP minimum (19 MiB, 2 passes, 1 lane).
    const salt = randomBytes(16);
    const tag = argon2Sync("argon2id", {
      message: "pw",
      nonce: salt,
      memory: 19_456,
      passes: 2,
      parallelism: 1,
      tagLength: 32,
    });
    const b64 = (b: Buffer) => b.toString("base64").replace(/=+$/, "");
    const stored = `$argon2id$v=19$m=19456,t=2,p=1$${b64(salt)}$${b64(tag)}`;
    expect(await verifyPassword(stored, "pw")).toBe(true);
    expect(await verifyPassword(stored, "PW")).toBe(false);
  });

  it("rejects foreign or tampered hashes instead of throwing", async () => {
    const hash = await hashPassword("pw");
    expect(await verifyPassword("scrypt:abc:def", "pw")).toBe(false);
    expect(await verifyPassword(hash.replace("argon2id", "argon2i"), "pw")).toBe(false);
    expect(await verifyPassword(hash.replace("m=65536", "m=9999999"), "pw")).toBe(false);
    expect(await verifyPassword(hash.replace("t=3", "t=99"), "pw")).toBe(false);
  });
});
