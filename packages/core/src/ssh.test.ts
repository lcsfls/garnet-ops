import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { fingerprint, generateDeployKey, parseKnownHosts } from "./ssh.ts";

function hasSshKeygen(): boolean {
  try {
    execFileSync("ssh-keygen", ["-?"], { stdio: "ignore" });
    return true;
  } catch (error) {
    // ssh-keygen exits non-zero on -?, but it exists.
    return (error as NodeJS.ErrnoException).code !== "ENOENT";
  }
}

describe("generateDeployKey", () => {
  it("writes an authorized_keys line with a sanitised comment", () => {
    const key = generateDeployKey("garnetops repo_1 evil\nline");
    expect(key.publicKey).toMatch(/^ssh-ed25519 [A-Za-z0-9+/]+=* garnetops-repo_1-evil-line$/);
    expect(key.privateKey).toMatch(
      /^-----BEGIN OPENSSH PRIVATE KEY-----\n[\s\S]+\n-----END OPENSSH PRIVATE KEY-----\n$/,
    );
  });

  it("creates a new key every time", () => {
    expect(generateDeployKey("a").publicKey).not.toBe(generateDeployKey("a").publicKey);
  });

  it.skipIf(!hasSshKeygen())(
    "produces a private key that OpenSSH reads and that matches the public key",
    () => {
      const dir = mkdtempSync(join(tmpdir(), "garnetops-ssh-"));
      try {
        const key = generateDeployKey("garnetops-test");
        const file = join(dir, "id");
        writeFileSync(file, key.privateKey, { mode: 0o600 });
        const derived = execFileSync("ssh-keygen", ["-y", "-f", file], { encoding: "utf8" }).trim();
        expect(key.publicKey.startsWith(derived.split(" ").slice(0, 2).join(" "))).toBe(true);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );
});

describe("parseKnownHosts", () => {
  const key = generateDeployKey("x").publicKey.split(" ")[1] as string;

  it("accepts plain entries with and without a port", () => {
    expect(
      parseKnownHosts(`git.example.test ssh-ed25519 ${key}\n[git.example.test]:2222 ssh-ed25519 ${key}\n`),
    ).toEqual([
      { host: "git.example.test", type: "ssh-ed25519", key },
      { host: "[git.example.test]:2222", type: "ssh-ed25519", key },
    ]);
  });

  it("rejects hashed hosts, markers, options and empty content", () => {
    expect(parseKnownHosts(`|1|abc=|def= ssh-ed25519 ${key}`)).toBeNull();
    expect(parseKnownHosts(`@revoked git.example.test ssh-ed25519 ${key}`)).toBeNull();
    expect(parseKnownHosts(`git.example.test ssh-ed25519 ${key} trailing`)).toBeNull();
    expect(parseKnownHosts("")).toBeNull();
  });
});

describe("fingerprint", () => {
  it.skipIf(!hasSshKeygen())("matches ssh-keygen", () => {
    const dir = mkdtempSync(join(tmpdir(), "garnetops-ssh-"));
    try {
      const line = generateDeployKey("fp").publicKey;
      const file = join(dir, "id.pub");
      writeFileSync(file, `${line}\n`);
      const out = execFileSync("ssh-keygen", ["-l", "-E", "sha256", "-f", file], { encoding: "utf8" });
      expect(out).toContain(fingerprint(line.split(" ")[1] as string));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
