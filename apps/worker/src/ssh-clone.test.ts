/**
 * SSH clone end to end against a local SSH server (ssh2) that serves a real
 * git repository through `git upload-pack`: the generated deploy key, host key
 * pinning on first contact, a changed host key and a refused key. Needs git and
 * an OpenSSH client; nothing leaves the machine.
 */
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fingerprint, generateDeployKey, parseKnownHosts } from "@garnetops/core/ssh";
import { Server, utils } from "ssh2";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { findSsh, shallowClone, sshClient } from "./git.ts";

const ready = Boolean(findSsh());

describe.skipIf(!ready)("clone over SSH with a deploy key", () => {
  const work = mkdtempSync(join(tmpdir(), "garnetops-ssh-clone-"));
  const repoDir = join(work, "origin");
  const hostKey = generateDeployKey("test-host");
  const deployKey = generateDeployKey("garnetops-test");
  const allowed = utils.parseKey(deployKey.publicKey);
  let server: Server;
  let url = "";
  let run = 0;
  let prHead = "";

  beforeAll(async () => {
    const git = (...args: string[]) => execFileSync("git", ["-C", repoDir, ...args], { stdio: "ignore" });
    await mkdir(repoDir);
    git("init", "-q", "-b", "main");
    writeFileSync(join(repoDir, "package.json"), '{"name":"fixture","version":"1.0.0"}\n');
    git("add", ".");
    git("-c", "user.name=t", "-c", "user.email=t@example.test", "commit", "-q", "-m", "fixture");
    // A pull request head as forges publish it: a commit that is not on any branch.
    git("checkout", "-q", "-b", "feature");
    writeFileSync(join(repoDir, "package.json"), '{"name":"fixture","version":"2.0.0"}\n');
    git("-c", "user.name=t", "-c", "user.email=t@example.test", "commit", "-q", "-am", "pull request");
    prHead = execFileSync("git", ["-C", repoDir, "rev-parse", "HEAD"]).toString().trim();
    git("update-ref", "refs/pull/1/head", "HEAD");
    git("checkout", "-q", "main");
    git("branch", "-q", "-D", "feature");

    server = new Server({ hostKeys: [hostKey.privateKey] }, (client) => {
      client.on("authentication", (ctx) => {
        if (ctx.method !== "publickey" || allowed instanceof Error) return ctx.reject(["publickey"]);
        const key = Array.isArray(allowed) ? allowed[0] : allowed;
        if (!key || ctx.key.algo !== key.type || !ctx.key.data.equals(key.getPublicSSH())) {
          return ctx.reject(["publickey"]);
        }
        if (!ctx.signature) return ctx.accept(); // key query before signing
        return key.verify(ctx.blob as Buffer, ctx.signature, ctx.hashAlgo) ? ctx.accept() : ctx.reject();
      });
      client.on("ready", () => {
        client.on("session", (accept) => {
          accept().on("exec", (acceptExec, reject, info) => {
            if (!/^git-upload-pack '\/?team\/app\.git'$/.test(info.command)) return reject();
            const stream = acceptExec();
            const child = spawn("git", ["upload-pack", repoDir], { stdio: ["pipe", "pipe", "pipe"] });
            stream.pipe(child.stdin);
            // Keep the channel open until the exit status is sent; git treats a missing one as an error.
            child.stdout.pipe(stream, { end: false });
            child.stderr.pipe(stream.stderr, { end: false });
            child.on("close", (code) => {
              stream.exit(code ?? 1);
              stream.end();
            });
          });
        });
      });
      client.on("error", () => {});
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    url = `ssh://git@127.0.0.1:${(server.address() as AddressInfo).port}/team/app.git`;
  });

  afterAll(() => {
    server?.close();
    rmSync(work, { recursive: true, force: true });
  });

  async function cloneWith(options: { knownHosts: string; pinned: boolean; key?: string; ref?: string }) {
    const dir = join(work, `run-${++run}`);
    await mkdir(join(dir, "home"), { recursive: true });
    const privateKeyFile = join(dir, "id_ed25519");
    const knownHostsFile = join(dir, "known_hosts");
    writeFileSync(privateKeyFile, options.key ?? deployKey.privateKey, { mode: 0o600 });
    writeFileSync(knownHostsFile, options.knownHosts, { mode: 0o600 });
    const client = await sshClient();
    const result = shallowClone({
      url,
      dir: join(dir, "src"),
      home: join(dir, "home"),
      branch: null,
      ref: options.ref ?? null,
      token: null,
      ssh: { ...client, privateKeyFile, knownHostsFile, pinned: options.pinned },
    });
    return { result, knownHostsFile, dir: join(dir, "src") };
  }

  it("offers a hybrid post-quantum key exchange first when the client has one", async () => {
    const { kex } = await sshClient();
    expect(kex.length).toBeGreaterThan(0);
    expect(kex.some((k) => k.includes("sha1"))).toBe(false);
    if (kex.includes("mlkem768x25519-sha256")) expect(kex[0]).toBe("mlkem768x25519-sha256");
  });

  it("clones on first contact and records the server's host key", async () => {
    const { result, knownHostsFile } = await cloneWith({ knownHosts: "", pinned: false });
    expect((await result).branch).toBe("main");
    const hosts = parseKnownHosts(readFileSync(knownHostsFile, "utf8"));
    expect(hosts).toHaveLength(1);
    const hostPublic = hostKey.publicKey.split(" ")[1] as string;
    expect(hosts?.[0]?.key).toBe(hostPublic);
    expect(fingerprint(hosts?.[0]?.key as string)).toBe(fingerprint(hostPublic));
  });

  it("clones again with the pinned key", async () => {
    const port = (server.address() as AddressInfo).port;
    const line = `[127.0.0.1]:${port} ${hostKey.publicKey.split(" ").slice(0, 2).join(" ")}\n`;
    const { result } = await cloneWith({ knownHosts: line, pinned: true });
    expect((await result).commitSha).toMatch(/^[0-9a-f]{40}$/);
  });

  it("fetches a pull request ref that is on no branch, shallow and detached", async () => {
    const { result, dir } = await cloneWith({ knownHosts: "", pinned: false, ref: "refs/pull/1/head" });
    const cloned = await result;
    expect(cloned.commitSha).toBe(prHead);
    expect(cloned.branch).toBe("refs/pull/1/head");
    expect(readFileSync(join(dir, "package.json"), "utf8")).toContain('"2.0.0"');
    const depth = execFileSync("git", ["-C", dir, "rev-list", "--count", "HEAD"]).toString().trim();
    expect(depth).toBe("1");
  });

  it("reports a ref the repository does not have", async () => {
    const { result } = await cloneWith({ knownHosts: "", pinned: false, ref: "refs/pull/99/head" });
    await expect(result).rejects.toThrow("The requested ref does not exist in the repository.");
  });

  it("refuses a ref that could be read as an option before running git", async () => {
    const { result } = await cloneWith({ knownHosts: "", pinned: false, ref: "--upload-pack=evil" });
    await expect(result).rejects.toThrow("Unsafe ref");
  });

  it("refuses a server whose host key differs from the pinned one", async () => {
    const port = (server.address() as AddressInfo).port;
    const other = generateDeployKey("impostor").publicKey.split(" ").slice(0, 2).join(" ");
    const { result } = await cloneWith({ knownHosts: `[127.0.0.1]:${port} ${other}\n`, pinned: true });
    await expect(result).rejects.toThrow(/host key does not match the pinned key/);
  });

  it("reports a key the server does not accept, without echoing ssh output", async () => {
    const { result } = await cloneWith({
      knownHosts: "",
      pinned: false,
      key: generateDeployKey("unknown").privateKey,
    });
    await expect(result).rejects.toThrow(
      "The server refused the deploy key. Add the public key to the repository as a read-only deploy key.",
    );
  });
});
