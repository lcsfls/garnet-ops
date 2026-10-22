/**
 * The forge client against a fake forge on loopback (HTTPS, throw-away certificate made with
 * openssl): both API flavours, every error status, redirects, oversized and endless answers,
 * time limits, the address policy and TLS verification. No database. Needs openssl.
 */
import { execFileSync } from "node:child_process";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { blobSha, FakeForge, FORGE_HOST } from "../test/fake-forge.ts";
import {
  branchHead,
  createBranch,
  deleteBranch,
  type ForgeError,
  type ForgeTarget,
  LIMITS,
  openPullRequest,
  pullRequestState,
  readFile,
  repoInfo,
  setForgeTestHooks,
  writeFile,
} from "./forge.ts";

let openssl = true;
try {
  execFileSync("openssl", ["version"], { stdio: "ignore" });
} catch {
  openssl = false;
}

const TOKEN = "test-token-0123456789abcdef";
const MANIFEST = '{"dependencies":{"lodash":"^4.17.20"}}\n';

async function code(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
    return "ok";
  } catch (error) {
    return (error as ForgeError).code ?? `unexpected:${String(error)}`;
  }
}

describe.skipIf(!openssl).each([
  ["github", "github" as const],
  ["gitea", "gitea" as const],
])("forge client (%s)", (_name, flavour) => {
  let forge: FakeForge;
  let target: ForgeTarget;

  beforeAll(async () => {
    forge = await new FakeForge(flavour, TOKEN, "team", "app", {
      files: { "package.json": MANIFEST },
    }).start();
    // The configured address is a private one; the socket goes to loopback.
    setForgeTestHooks({
      resolve: async () => ["192.168.1.20"],
      connectTo: () => "127.0.0.1",
      ca: forge.ca,
    });
    target = { kind: flavour, apiBaseUrl: forge.apiBase, token: TOKEN, owner: "team", repo: "app" };
  });
  afterAll(async () => {
    setForgeTestHooks(null);
    await forge.stop();
  });
  afterEach(() => {
    forge.faults.length = 0;
    forge.requests.length = 0;
  });

  it("reads the repository, a branch and a file", async () => {
    expect(await repoInfo(target)).toEqual({
      defaultBranch: "main",
      archived: false,
      canPush: true,
      broadToken: false,
    });
    const head = await branchHead(target, "main");
    expect(head).toMatch(/^[0-9a-f]{40}$/);
    const file = await readFile(target, "package.json", "main");
    expect(file.sha).toBe(blobSha(MANIFEST));
    expect(file.bytes.toString("utf8")).toBe(MANIFEST);
    expect(forge.requests.every((r) => r.authorization === forge.authorization)).toBe(true);
    // The host name is what the certificate and the Host header were checked against.
    expect(forge.requests.length).toBe(3);
  });

  it("creates a branch, replaces the file with the sha precondition, opens and reads a pull request, deletes the branch", async () => {
    const head = await branchHead(target, "main");
    await createBranch(target, "garnetops/fix-lodash-4.17.21", { branch: "main", sha: head });
    const edited = MANIFEST.replace("^4.17.20", "^4.17.21");
    await writeFile(target, {
      path: "package.json",
      branch: "garnetops/fix-lodash-4.17.21",
      sha: blobSha(MANIFEST),
      bytes: Buffer.from(edited),
      message: "fix(deps): update lodash to 4.17.21",
    });
    expect(forge.fileOn("garnetops/fix-lodash-4.17.21", "package.json")).toBe(edited);
    expect(forge.fileOn("main", "package.json")).toBe(MANIFEST);
    const number = await openPullRequest(target, {
      title: "Update",
      body: "Body",
      head: "garnetops/fix-lodash-4.17.21",
      base: "main",
    });
    expect(number).toBe(1);
    expect(await pullRequestState(target, 1)).toBe("open");
    forge.setPull(1, { merged: true, state: "closed" });
    expect(await pullRequestState(target, 1)).toBe("merged");
    forge.setPull(1, { merged: false, state: "closed" });
    expect(await pullRequestState(target, 1)).toBe("closed");
    await deleteBranch(target, "garnetops/fix-lodash-4.17.21");
    expect(forge.branches.has("garnetops/fix-lodash-4.17.21")).toBe(false);
    // Nothing but the branch we made was ever written.
    const writes = forge.requests.filter((r) => r.method !== "GET");
    expect(writes.map((r) => `${r.method} ${r.path.replace(forge.prefix, "")}`)).toEqual(
      flavour === "github"
        ? [
            "POST /repos/team/app/git/refs",
            "PUT /repos/team/app/contents/package.json",
            "POST /repos/team/app/pulls",
            "DELETE /repos/team/app/git/refs/heads/garnetops/fix-lodash-4.17.21",
          ]
        : [
            "POST /repos/team/app/branches",
            "PUT /repos/team/app/contents/package.json",
            "POST /repos/team/app/pulls",
            "DELETE /repos/team/app/branches/garnetops/fix-lodash-4.17.21",
          ],
    );
  });

  it("a write against a file that moved on is refused by the forge (sha precondition)", async () => {
    const head = await branchHead(target, "main");
    await createBranch(target, "stale-branch", { branch: "main", sha: head });
    const result = await code(
      writeFile(target, {
        path: "package.json",
        branch: "stale-branch",
        sha: blobSha("an older version of the file"),
        bytes: Buffer.from("{}"),
        message: "x",
      }),
    );
    expect(["conflict", "rejected"]).toContain(result);
    expect(forge.fileOn("stale-branch", "package.json")).toBe(MANIFEST);
  });

  it("a branch that exists cannot be created again", async () => {
    const head = await branchHead(target, "main");
    await createBranch(target, "twice", { branch: "main", sha: head });
    expect(["conflict", "rejected"]).toContain(
      await code(createBranch(target, "twice", { branch: "main", sha: head })),
    );
  });

  it.each([
    [401, "token-rejected"],
    [403, "forbidden"],
    [404, "not-found"],
    [409, "conflict"],
    [422, "rejected"],
    [429, "rate-limited"],
    [500, "http-error"],
    [503, "http-error"],
  ])("status %i becomes %s, and the body is never read", async (status, expected) => {
    forge.faults.push({ match: /^GET /, status });
    expect(await code(repoInfo(target))).toBe(expected);
  });

  it("a 403 with an exhausted rate limit is a rate limit", async () => {
    forge.faults.push({ match: /^GET /, status: 403, headers: { "x-ratelimit-remaining": "0" } });
    expect(await code(repoInfo(target))).toBe("rate-limited");
    forge.faults.push({ match: /^GET /, status: 403, headers: { "retry-after": "30" } });
    expect(await code(repoInfo(target))).toBe("rate-limited");
  });

  it("the error carries a code, never the forge's text", async () => {
    forge.faults.push({ match: /^GET /, status: 500, body: "stack trace with /srv/secret and the token" });
    try {
      await repoInfo(target);
      expect.unreachable();
    } catch (error) {
      expect(String((error as Error).message)).toBe("http-error");
      expect(JSON.stringify(error)).not.toContain("secret");
    }
  });

  it("redirects are not followed, so the token never goes to another host", async () => {
    forge.faults.push({ match: /^GET /, status: 302, headers: { location: "https://evil.example/steal" } });
    expect(await code(repoInfo(target))).toBe("redirect");
    forge.faults.push({
      match: /^GET /,
      status: 307,
      headers: { location: `https://${FORGE_HOST}:${forge.port}/elsewhere` },
    });
    expect(await code(repoInfo(target))).toBe("redirect");
    expect(forge.requests).toHaveLength(2);
  });

  it("an answer that is not JSON, or not the expected shape, is a bad response", async () => {
    forge.faults.push({ match: /^GET /, status: 200, body: "<html>login</html>" });
    expect(await code(repoInfo(target))).toBe("bad-response");
    forge.faults.push({ match: /^GET /, status: 200, body: JSON.stringify({ unexpected: true }) });
    expect(await code(repoInfo(target))).toBe("bad-response");
    forge.faults.push({ match: /contents/, status: 200, body: JSON.stringify([{ type: "dir" }]) });
    expect(await code(readFile(target, "package.json", "main"))).toBe("bad-response");
    forge.faults.push({
      match: /contents/,
      status: 200,
      body: JSON.stringify({
        type: "file",
        sha: "a".repeat(40),
        size: 5_000_000,
        encoding: "none",
        content: "",
      }),
    });
    expect(await code(readFile(target, "package.json", "main"))).toBe("bad-response");
  });

  it("a file over the manifest limit is refused", async () => {
    forge.faults.push({
      match: /contents/,
      status: 200,
      body: JSON.stringify({
        type: "file",
        sha: "a".repeat(40),
        size: 2_000_000,
        encoding: "base64",
        content: "AAAA",
      }),
    });
    expect(await code(readFile(target, "package.json", "main"))).toBe("too-large");
  });

  it("an oversized or endless answer is cut off", async () => {
    forge.faults.push({ match: /^GET /, action: "huge" });
    expect(await code(repoInfo(target))).toBe("too-large");
    forge.faults.push({ match: /^GET /, action: "endless" });
    expect(await code(repoInfo(target))).toBe("too-large");
  });

  it("a server that never answers ends with a timeout", async () => {
    const before = { ...LIMITS };
    LIMITS.firstByteMs = 300;
    LIMITS.totalMs = 600;
    try {
      forge.faults.push({ match: /^GET /, action: "hang" });
      expect(await code(repoInfo(target))).toBe("timeout");
    } finally {
      Object.assign(LIMITS, before);
    }
  });

  it("a token with line breaks or spaces is never sent", async () => {
    for (const token of [
      "abc\r\nx-evil: 1",
      "has space in it",
      "short",
      "x".repeat(600),
      "tok\u0000en-0123456789",
    ]) {
      expect(await code(repoInfo({ ...target, token }))).toBe("token-rejected");
    }
    expect(forge.requests).toHaveLength(0);
  });

  it("owner and repository names cannot reshape the path", async () => {
    for (const owner of ["../x", "a/b", "a b", "a?b", ""]) {
      expect(await code(repoInfo({ ...target, owner }))).toBe("not-found");
    }
    expect(forge.requests).toHaveLength(0);
  });

  it("a file path is encoded per segment", async () => {
    await code(readFile(target, "dir with space/pa?th#x/package.json", "feature/x y"));
    expect(forge.requests[0]?.path).toContain("/contents/dir%20with%20space/pa%3Fth%23x/package.json");
    expect(forge.requests[0]?.query).toBe("?ref=feature%2Fx%20y");
  });
});

describe.skipIf(!openssl)("address policy and TLS", () => {
  let forge: FakeForge;
  beforeAll(async () => {
    forge = await new FakeForge("gitea", TOKEN, "team", "app", {
      files: { "package.json": MANIFEST },
    }).start();
  });
  afterAll(async () => {
    setForgeTestHooks(null);
    await forge.stop();
  });
  afterEach(() => {
    forge.requests.length = 0;
  });

  const at = (apiBaseUrl: string): ForgeTarget => ({
    kind: "gitea",
    apiBaseUrl,
    token: TOKEN,
    owner: "team",
    repo: "app",
  });

  it.each([
    ["https://127.0.0.1/api/v1"],
    ["https://localhost/api/v1"],
    ["https://forge.localhost/api/v1"],
    ["https://169.254.169.254/api/v1"],
    ["https://[::1]/api/v1"],
    ["https://[fe80::1]/api/v1"],
    ["https://[::ffff:127.0.0.1]/api/v1"],
    ["https://[::ffff:169.254.169.254]/api/v1"],
    ["https://0.0.0.0/api/v1"],
    ["https://224.0.0.1/api/v1"],
    ["https://2130706433/api/v1"],
    ["http://192.168.1.20/api/v1"],
    ["ftp://192.168.1.20/api/v1"],
    ["https://user:pw@192.168.1.20/api/v1"],
  ])("never connects to %s", async (url) => {
    setForgeTestHooks({ connectTo: () => "127.0.0.1", ca: forge.ca });
    expect(await code(repoInfo(at(url)))).toBe("address-refused");
    expect(forge.requests).toHaveLength(0);
  });

  it("refuses a name that resolves to a forbidden address, even if another answer is fine", async () => {
    setForgeTestHooks({
      resolve: async () => ["192.168.1.20", "169.254.169.254"],
      connectTo: () => "127.0.0.1",
      ca: forge.ca,
    });
    expect(await code(repoInfo(at(`https://${FORGE_HOST}:${forge.port}/api/v1`)))).toBe("address-refused");
    setForgeTestHooks({ resolve: async () => ["127.0.0.1"], connectTo: () => "127.0.0.1", ca: forge.ca });
    expect(await code(repoInfo(at(`https://${FORGE_HOST}:${forge.port}/api/v1`)))).toBe("address-refused");
    setForgeTestHooks({ resolve: async () => [], connectTo: () => "127.0.0.1", ca: forge.ca });
    expect(await code(repoInfo(at(`https://${FORGE_HOST}:${forge.port}/api/v1`)))).toBe("unresolvable");
    expect(forge.requests).toHaveLength(0);
  });

  it("connects to the address that was checked", async () => {
    const connected: string[] = [];
    setForgeTestHooks({
      resolve: async () => ["10.20.30.40", "192.168.7.7"],
      connectTo: (address) => {
        connected.push(address);
        return "127.0.0.1";
      },
      ca: forge.ca,
    });
    expect(await code(repoInfo(at(`https://${FORGE_HOST}:${forge.port}/api/v1`)))).toBe("ok");
    expect(connected).toEqual(["10.20.30.40"]);
  });

  it("a certificate that is not trusted is refused: verification cannot be switched off", async () => {
    setForgeTestHooks({ resolve: async () => ["192.168.1.20"], connectTo: () => "127.0.0.1" });
    expect(await code(repoInfo(at(`https://${FORGE_HOST}:${forge.port}/api/v1`)))).toBe("tls");
    expect(forge.requests).toHaveLength(0);
  });

  it("a certificate for another name is refused", async () => {
    setForgeTestHooks({ resolve: async () => ["192.168.1.20"], connectTo: () => "127.0.0.1", ca: forge.ca });
    expect(await code(repoInfo(at(`https://other.example.test:${forge.port}/api/v1`)))).toBe("tls");
  });

  it("an unreachable server is a connection failure", async () => {
    setForgeTestHooks({ resolve: async () => ["192.168.1.20"], connectTo: () => "127.0.0.1", ca: forge.ca });
    expect(await code(repoInfo(at("https://forge.example.test:1/api/v1")))).toBe("connection-failed");
  });
});
