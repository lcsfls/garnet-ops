/**
 * The proof file's redirects (ADR 0023): never followed, but where they point is named so an owner knows what to fix. Against a
 * plain HTTP server on loopback for an address asset (HTTPS is tried first and finds a closed port). No database, nothing leaves
 * the machine.
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { VERIFY_FILE_PATH } from "@garnetops/core/exposure";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { closedPort } from "../test/exposure-fixtures.ts";
import { fetchProofFile, type NetEnv } from "./exposure-net.ts";

describe("the proof file's redirects", () => {
  let server: Server;
  let env: NetEnv;
  const answer: { status: number; location: string | null } = { status: 302, location: null };
  const requests: string[] = [];

  beforeAll(async () => {
    server = createServer((req, res) => {
      requests.push(String(req.url));
      const headers: Record<string, string> = answer.location === null ? {} : { location: answer.location };
      res.writeHead(answer.status, headers).end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    env = {
      dns: {} as NetEnv["dns"],
      allowTestRanges: true,
      httpsPort: await closedPort(),
      httpPort: (server.address() as AddressInfo).port,
    };
  });
  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  const fetchWith = async (status: number, location: string | null) => {
    answer.status = status;
    answer.location = location;
    requests.length = 0;
    const result = await fetchProofFile(
      env,
      { value: "127.0.0.1", isAddress: true },
      ["127.0.0.1"],
      VERIFY_FILE_PATH,
    );
    // Exactly one request, for the proof file: the redirect is never followed.
    expect(requests).toEqual([VERIFY_FILE_PATH]);
    return result;
  };

  it("names another host, and keeps nothing of its path or query", async () => {
    const result = await fetchWith(
      301,
      "https://www.example.com/.well-known/garnetops-verify.txt?session=abc",
    );
    expect(result).toEqual({
      ok: false,
      error: "fileRedirected",
      redirect: { kind: "otherHost", host: "www.example.com" },
    });
    expect(JSON.stringify(result)).not.toContain("session");
  });

  it("tells a redirect on the same site (another page, a trailing slash, another scheme) from another host", async () => {
    for (const location of [
      "/",
      "/.well-known/garnetops-verify.txt/",
      "https://127.0.0.1/.well-known/garnetops-verify.txt",
    ]) {
      expect(await fetchWith(302, location)).toEqual({
        ok: false,
        error: "fileRedirected",
        redirect: { kind: "sameHost" },
      });
    }
  });

  it("says when a Location cannot be used", async () => {
    for (const location of [
      null,
      "javascript:alert(1)",
      "https://bad_host!.example.com/",
      `https://${"a".repeat(300)}.example.com/`,
    ]) {
      expect(await fetchWith(307, location)).toEqual({
        ok: false,
        error: "fileRedirected",
        redirect: { kind: "unusable" },
      });
    }
  });

  it("still reports a missing file as such", async () => {
    expect(await fetchWith(404, null)).toEqual({ ok: false, error: "fileNotFound" });
  });
});
