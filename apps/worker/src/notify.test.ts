/**
 * Webhook delivery against a local HTTPS server (a throw-away self-signed certificate made
 * with openssl), the address policy, and the texts. Needs openssl; nothing leaves the machine.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { NotifyPayload } from "@garnetops/core/notifications";
import { generateVaultKeyPair } from "@garnetops/core/vault";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const work = mkdtempSync(join(tmpdir(), "garnetops-notify-test-"));
let openssl = true;
try {
  execFileSync("openssl", ["version"], { stdio: "ignore" });
} catch {
  openssl = false;
}

const payload: NotifyPayload = {
  event: "finding.new_critical",
  organization: "Example Org",
  repository: { id: "repo_1", name: "billing-portal" },
  counts: { critical: 2, knownExploited: 1 },
  link: "https://garnetops.example.com/repositories/repo_1",
  at: "2026-10-21T10:00:00.000Z",
};

describe.skipIf(!openssl)("notifications in the worker", () => {
  let server: Server;
  let port = 0;
  let ca = "";
  const received: { path: string; body: unknown }[] = [];
  let mod: typeof import("./notify.ts");

  beforeAll(async () => {
    const keyFile = join(work, "key.pem");
    const certFile = join(work, "cert.pem");
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=hooks.example.test",
        "-addext",
        "subjectAltName=DNS:hooks.example.test",
        "-keyout",
        keyFile,
        "-out",
        certFile,
      ],
      { stdio: "ignore" },
    );
    ca = readFileSync(certFile, "utf8");
    server = createServer({ key: readFileSync(keyFile), cert: ca }, (req, res) => {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", () => {
        received.push({ path: req.url ?? "", body: body ? JSON.parse(body) : null });
        if (req.url === "/redirect") {
          res.writeHead(302, { location: "https://hooks.example.test/elsewhere" }).end();
        } else if (req.url === "/slow") {
          // never answers
        } else if (req.url === "/missing") {
          res.writeHead(404).end("secret details in the body");
        } else {
          res.writeHead(204).end();
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
    const vaultKey = join(work, "vault.pem");
    writeFileSync(vaultKey, generateVaultKeyPair().privateKeyPem, { mode: 0o600 });
    Object.assign(process.env, {
      DATABASE_URL: "postgres://unused@127.0.0.1:1/unused",
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: vaultKey,
      GARNETOPS_GRYPE_BIN: "unused",
      GARNETOPS_GRYPE_DB_DIR: work,
    });
    mod = await import("./notify.ts");
  });

  afterAll(() => {
    server?.close();
    rmSync(work, { recursive: true, force: true });
  });

  // The test server sits on 127.0.0.1, which the real lookup refuses; this one maps the test name to it.
  const toTestServer: Parameters<typeof import("./notify.ts")["postJson"]>[2] = {
    get ca() {
      return ca;
    },
    lookup: (_host, options, callback) => {
      if ((options as { all?: boolean }).all) callback(null, [{ address: "127.0.0.1", family: 4 }]);
      else callback(null, "127.0.0.1", 4);
    },
  };
  const url = (path: string) => `https://hooks.example.test:${port}${path}`;

  it("posts the Discord body and treats 2xx as delivered", async () => {
    const { title, text } = mod.renderNotification(payload, "en");
    await mod.postJson(
      url("/discord"),
      (await import("@garnetops/core/notifications")).webhookBody("discord", payload, title, text),
      toTestServer,
    );
    const last = received.at(-1);
    expect(last?.path).toBe("/discord");
    expect(last?.body).toMatchObject({ allowed_mentions: { parse: [] } });
    expect(JSON.stringify(last?.body)).not.toMatch(/CVE-|GHSA-/);
  });

  it("does not follow redirects and keeps no response body", async () => {
    await expect(mod.postJson(url("/redirect"), {}, toTestServer)).rejects.toThrow(
      "HTTP 302 (redirects are not followed)",
    );
    expect(received.some((r) => r.path === "/elsewhere")).toBe(false);
    await expect(mod.postJson(url("/missing"), {}, toTestServer)).rejects.toThrow(/^HTTP 404$/);
  });

  it("refuses http, credentials in the URL and loopback names before connecting", async () => {
    await expect(mod.postJson(`http://hooks.example.test:${port}/x`, {}, toTestServer)).rejects.toThrow(
      /https/,
    );
    await expect(mod.postJson("https://localhost/x", {}, toTestServer)).rejects.toThrow(
      "This address is not allowed",
    );
  });

  it("the real lookup refuses a name that resolves to loopback (checked when connecting)", async () => {
    const code = await new Promise<string>((resolve) =>
      mod.safeLookup("localhost", {}, (error) =>
        resolve(error ? String((error as NodeJS.ErrnoException).code) : "ok"),
      ),
    );
    expect(code).toBe("EREFUSED_ADDRESS");
  });

  it("gives up after the timeout", { timeout: 15_000 }, async () => {
    await expect(mod.postJson(url("/slow"), {}, toTestServer)).rejects.toThrow("timeout");
  });

  it("writes the summary in the channel's language, without vulnerability details", () => {
    const en = mod.renderNotification(payload, "en");
    expect(en.title).toBe("New critical vulnerabilities: billing-portal");
    expect(en.text).toContain("2 critical, 1 known to be exploited");
    const de = mod.renderNotification(
      { ...payload, event: "gate.blocked", gate: { blockingRules: 1 } },
      "de",
    );
    expect(de.title).toBe("Quality Gate blockiert: billing-portal");
    expect(de.text).toContain("Example Org");
  });
});
