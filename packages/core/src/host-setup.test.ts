import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { renderSetupScript, setupOneLiner, WRAPPER_SCRIPT, WRAPPER_SHA256 } from "./host-setup.ts";
import { parseInventoryReport } from "./hosts.ts";
import { fingerprint, generateDeployKey } from "./ssh.ts";

const key = generateDeployKey("garnetops-host-access");
const render = (allowedSource = "192.0.2.10") =>
  renderSetupScript({ publicKey: key.publicKey, allowedSource });
const posix = process.platform !== "win32" && spawnSync("sh", ["-c", "true"]).status === 0;

describe("renderSetupScript", () => {
  const out = render("192.0.2.0/24, 2001:DB8::/32");

  it("writes one restricted authorized_keys line with the source addresses and the forced command", () => {
    expect(out.script).toContain('ALLOWED_SOURCE="192.0.2.0/24,2001:db8::/32"');
    expect(out.script).toContain(`PUBLIC_KEY="${key.publicKey}"`);
    expect(out.script).toContain(
      `printf 'restrict,from="%s",command="%s" %s\\n' "$ALLOWED_SOURCE" "$WRAPPER" "$PUBLIC_KEY"`,
    );
    expect(out.script).toContain('WRAPPER="/usr/local/lib/garnetops/inventory"');
    expect(out.script).toContain('SSH_USER="garnetops"');
  });

  it("names the key by its fingerprint and the wrapper by its checksum", () => {
    expect(out.keyFingerprint).toBe(fingerprint(key.publicKey.split(" ")[1] as string));
    expect(out.script).toContain(`Access key fingerprint : ${out.keyFingerprint}`);
    expect(out.script).toContain(`WRAPPER_SHA256="${WRAPPER_SHA256}"`);
    expect(out.wrapperSha256).toBe(WRAPPER_SHA256);
  });

  it("is deterministic, so one checksum identifies it", () => {
    expect(render().script).toBe(render().script);
    expect(render().sha256).toBe(createHash("sha256").update(render().script).digest("hex"));
    expect(render("192.0.2.11").sha256).not.toBe(render("192.0.2.10").sha256);
  });

  it("carries no secret: no private key, no token, no time", () => {
    expect(out.script).not.toContain("PRIVATE KEY");
    expect(out.script).not.toMatch(/bearer|authorization|password=|BEGIN [A-Z ]*KEY/i);
    expect(out.script).not.toMatch(/\d{4}-\d{2}-\d{2}T/);
  });

  it("embeds the wrapper unchanged", () => {
    const body = out.script.split("<<'GARNETOPS_WRAPPER_END'\n")[1]?.split("GARNETOPS_WRAPPER_END\n")[0];
    expect(body).toBe(WRAPPER_SCRIPT);
    expect(
      createHash("sha256")
        .update(body ?? "")
        .digest("hex"),
    ).toBe(WRAPPER_SHA256);
  });

  it("checks root, uses set -eu, installs the checksum check and an uninstall option", () => {
    expect(out.script).toContain("\nset -eu\n");
    expect(out.script).toContain('[ "$(id -u)" -eq 0 ] || die');
    expect(out.script).toContain("--uninstall");
    expect(out.script).toContain("sha256sum");
    expect(out.script).toContain("userdel");
  });

  it("makes no network call of its own", () => {
    expect(out.script).not.toMatch(/\b(curl|wget|nc|ncat|socat)\b/);
    expect(WRAPPER_SCRIPT).not.toMatch(/\b(curl|wget|nc|ncat|socat|ssh|sudo|su)\b/);
  });

  it("refuses anything but an Ed25519 public key and a valid source", () => {
    const attempt = (publicKey: string, allowedSource: string) => () =>
      renderSetupScript({ publicKey, allowedSource });
    expect(attempt("ssh-rsa AAAAB3NzaC1yc2E x", "192.0.2.1")).toThrow(/Ed25519/);
    expect(attempt(`${key.publicKey}"; rm -rf / #`, "192.0.2.1")).toThrow(/Ed25519/);
    expect(attempt(`${key.publicKey}\nssh-ed25519 AAAA other`, "192.0.2.1")).toThrow(/Ed25519/);
    expect(attempt(key.publicKey, "")).toThrow(/allowed source/);
    expect(attempt(key.publicKey, "0.0.0.0/0")).toThrow(/allowed source/);
    expect(attempt(key.publicKey, '192.0.2.1"; id; "')).toThrow(/allowed source/);
    expect(attempt(key.publicKey, "$(id)")).toThrow(/allowed source/);
  });
});

describe("setupOneLiner", () => {
  it("downloads, checks the SHA-256 and only then runs the script", () => {
    const sha = "a".repeat(64);
    expect(setupOneLiner("https://garnetops.example.com/api/v1/host-setup/abc_DEF-123", sha)).toBe(
      `curl -fsSLo garnetops-host-setup.sh 'https://garnetops.example.com/api/v1/host-setup/abc_DEF-123' && echo "${sha}  garnetops-host-setup.sh" | sha256sum -c - && sudo sh garnetops-host-setup.sh`,
    );
  });

  it("quotes the URL and refuses a value that is not a SHA-256", () => {
    expect(setupOneLiner("https://x.example/a'b", "b".repeat(64))).toContain(`'https://x.example/a'\\''b'`);
    expect(() => setupOneLiner("https://x.example", "nothex")).toThrow();
    expect(() => setupOneLiner("https://x.example", `${"a".repeat(64)}; id`)).toThrow();
  });
});

describe.skipIf(!posix)("the scripts as a shell sees them", () => {
  const dir = mkdtempSync(join(tmpdir(), "garnetops-setup-test-"));
  const wrapper = join(dir, "inventory");
  const setup = join(dir, "setup.sh");
  writeFileSync(wrapper, WRAPPER_SCRIPT, { mode: 0o755 });
  writeFileSync(setup, render().script);
  const sh = (args: string[], env: Record<string, string> = {}) =>
    spawnSync("sh", args, {
      env: { PATH: process.env.PATH ?? "", ...env },
      encoding: "utf8",
      timeout: 60_000,
    });

  it("both parse as POSIX sh", () => {
    expect(sh(["-n", wrapper]).status).toBe(0);
    expect(sh(["-n", setup]).status).toBe(0);
    rmSync(join(dir, "unused"), { force: true });
  });

  it("the wrapper answers only the exact word inventory", () => {
    for (const command of [
      undefined,
      "",
      "id",
      "inventory ",
      "inventory; id",
      "Inventory",
      "inventory\nid",
      "sh",
      "-V",
    ]) {
      const result = sh([wrapper], command === undefined ? {} : { SSH_ORIGINAL_COMMAND: command });
      expect(result.status, JSON.stringify(command)).toBe(2);
      expect(result.stdout, JSON.stringify(command)).toBe("");
    }
  });

  it("the wrapper's report parses with the platform's parser", () => {
    const result = sh([wrapper], { SSH_ORIGINAL_COMMAND: "inventory" });
    expect(result.status).toBe(0);
    expect(result.stdout.startsWith("GARNETOPS-INVENTORY 1\n")).toBe(true);
    expect(result.stdout.endsWith("@@end\n")).toBe(true);
    const report = parseInventoryReport(result.stdout);
    expect(report.kernel).not.toBeNull();
    expect(report.arch).not.toBeNull();
  });

  it("the setup script refuses to run without root, and explains itself with --help", () => {
    if (process.getuid?.() !== 0) {
      const result = sh([setup]);
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("must run as root");
    }
    const help = sh([setup, "--help"]);
    expect(help.status).toBe(0);
    expect(help.stdout).toContain("--uninstall");
    expect(sh([setup, "--bogus"]).status).toBe(2);
  });
});
