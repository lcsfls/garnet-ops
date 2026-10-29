/**
 * The scanner service (ADR 0028) and the worker's client, over a real Unix socket, with stand-ins
 * for syft and grype that only write what they were asked for.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  requestMatch,
  requestMatchPurls,
  requestSbom,
  ScannerRequestError,
  ScannerUnavailableError,
  scannerHealth,
} from "./scanner-client.ts";
import { byteLimit, createScannerService, purlList } from "./scanner-service.ts";

const root = mkdtempSync(join(tmpdir(), "garnetops-scanner-test-"));
const work = join(root, "work");
const out = join(root, "out");
const bin = join(root, "bin");
const socket = join(root, "scanner.sock");

// syft: `dir:<dir> -o syft-json=<file> -q`; fails when the clone holds a file named FAIL.
const fakeSyft = `#!/bin/sh
dir="\${1#dir:}"; file="\${3#syft-json=}"
[ -e "$dir/FAIL" ] && exit 3
printf '{"artifacts":[],"descriptor":{"version":"1.2.3"},"dir":"%s"}' "$dir" > "$file"
`;
// grype: `sbom:<file> -o json --file <out> -q`; wraps the SBOM it was given.
const fakeGrype = `#!/bin/sh
sbom="\${1#*:}"
{ printf '{"matches":[],"sbom":'; cat "$sbom"; printf '}'; } > "$5"
`;

function clone(name: string): string {
  const dir = join(work, name, "src");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), "{}");
  return `${name}/src`;
}

const server = createScannerService({
  workDir: work,
  grypeBin: join(bin, "grype"),
  syftBin: join(bin, "syft"),
  grypeDbDir: join(root, "db"),
  concurrency: 1,
  version: "0.0.9",
});

describe.skipIf(process.platform === "win32")("scanner service", () => {
  beforeAll(async () => {
    for (const dir of [work, out, bin]) mkdirSync(dir, { recursive: true });
    writeFileSync(join(bin, "syft"), fakeSyft, { mode: 0o755 });
    writeFileSync(join(bin, "grype"), fakeGrype, { mode: 0o755 });
    await new Promise<void>((resolve) => server.listen(socket, resolve));
  });
  afterAll(async () => {
    await new Promise((resolve) => server.close(resolve));
    rmSync(root, { recursive: true, force: true });
  });

  it("answers its health check with its release", async () => {
    expect(await scannerHealth(socket)).toEqual({ version: "0.0.9" });
  });

  it("builds an SBOM of a clone and matches it", async () => {
    const dir = clone("scan-Ab12Cd");
    const sbom = join(out, "sbom.json");
    const report = join(out, "grype.json");
    await requestSbom(socket, dir, sbom);
    expect(JSON.parse(readFileSync(sbom, "utf8"))).toMatchObject({ dir: join(work, dir) });
    await requestMatch(socket, sbom, report);
    expect(JSON.parse(readFileSync(report, "utf8"))).toMatchObject({
      matches: [],
      sbom: { descriptor: { version: "1.2.3" } },
    });
  });

  it("runs requests one after another at concurrency 1", async () => {
    const dirs = ["scan-aaaaaa", "scan-bbbbbb", "scan-cccccc"].map(clone);
    await Promise.all(dirs.map((dir, i) => requestSbom(socket, dir, join(out, `sbom-${i}.json`))));
    dirs.forEach((dir, i) => {
      expect(JSON.parse(readFileSync(join(out, `sbom-${i}.json`), "utf8")).dir).toBe(join(work, dir));
    });
  });

  it.each([
    ["../etc", "bad_request"],
    ["scan-Ab12Cd/src/..", "bad_request"],
    ["scan-Ab12Cd/other", "bad_request"],
    ["/etc", "bad_request"],
    ["scan-toolong1/src", "bad_request"],
    [42, "bad_request"],
    ["scan-zzzzzz/src", "not_found"],
  ])("refuses the directory %j (%s)", async (dir, code) => {
    const error = await requestSbom(socket, dir as string, join(out, "x.json")).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ScannerRequestError);
    expect((error as ScannerRequestError).code).toBe(code);
  });

  it("does not follow a clone directory that links out of the work directory", async () => {
    const outside = join(root, "outside");
    mkdirSync(outside, { recursive: true });
    mkdirSync(join(work, "scan-Link01"), { recursive: true });
    symlinkSync(outside, join(work, "scan-Link01", "src"));
    const error = await requestSbom(socket, "scan-Link01/src", join(out, "x.json")).catch((e: unknown) => e);
    expect((error as ScannerRequestError).code).toBe("bad_request");
  });

  it("reports a failed syft as a code, without its output", async () => {
    const dir = clone("scan-Fail01");
    writeFileSync(join(work, dir, "FAIL"), "");
    const error = await requestSbom(socket, dir, join(out, "x.json")).catch((e: unknown) => e);
    expect((error as ScannerRequestError).code).toBe("sbom_failed");
  });

  it("matches a list of package URLs and refuses anything that is not one (ADR 0029)", async () => {
    const list = join(out, "list.purls");
    writeFileSync(list, "pkg:npm/lodash@4.17.20\npkg:npm/left-pad@1.3.0\n");
    await requestMatchPurls(socket, list, join(out, "purls.json"));
    const answer = readFileSync(join(out, "purls.json"), "utf8");
    expect(answer).toContain("pkg:npm/lodash@4.17.20");
    for (const bad of ["--help\n", "pkg:npm/a b\n", "\n", "/etc/passwd\n"]) {
      writeFileSync(list, bad);
      const error = await requestMatchPurls(socket, list, join(out, "x.json")).catch((e: unknown) => e);
      expect((error as ScannerRequestError).code).toBe("bad_request");
    }
    expect(purlList(" pkg:npm/x@1 \n\n pkg:pypi/y@2 ")).toBe("pkg:npm/x@1\npkg:pypi/y@2\n");
  });

  it("is unavailable, not failed, when nothing listens", async () => {
    const missing = join(root, "missing.sock");
    expect(await scannerHealth(missing)).toBeNull();
    const error = await requestSbom(missing, "scan-Ab12Cd/src", join(out, "x.json")).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ScannerUnavailableError);
  });
});

describe("byteLimit", () => {
  it("passes a stream up to the limit and fails beyond it", async () => {
    const collect = async (size: number) => {
      const chunks: Buffer[] = [];
      for await (const chunk of Readable.from([Buffer.alloc(size)]).pipe(
        byteLimit(10, () => new Error("too large")),
      ))
        chunks.push(chunk as Buffer);
      return Buffer.concat(chunks).length;
    };
    expect(await collect(10)).toBe(10);
    await expect(collect(11)).rejects.toThrow("too large");
  });
});
