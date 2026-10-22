/**
 * The SBOM built from a server inventory, read by the real syft and grype binaries
 * (`pnpm scanners:fetch`). Skipped when a binary is missing; the grype test also needs the
 * local vulnerability database (`pnpm scanners:fetch -- --with-db`).
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildHostSbom, parseInventoryReport, REPORT_HEADER } from "@garnetops/core/hosts";
import { afterAll, describe, expect, it, vi } from "vitest";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const exe = process.platform === "win32" ? ".exe" : "";
const syftBin = join(root, ".tools", "syft", `syft${exe}`);
const grypeBin = join(root, ".tools", "grype", `grype${exe}`);
const grypeDb = join(root, ".tools", "grype-db");
const haveDb = existsSync(join(grypeDb, "6", "vulnerability.db"));

vi.mock("./env.ts", () => ({
  env: { GARNETOPS_GRYPE_BIN: grypeBin, GARNETOPS_GRYPE_DB_DIR: grypeDb },
}));

const T = "\t";
const report = parseInventoryReport(
  [
    REPORT_HEADER,
    "@@section os-release",
    "ID=debian",
    "VERSION_ID=12",
    "VERSION_CODENAME=bookworm",
    'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"',
    "@@section machine",
    "x86_64",
    "@@section dpkg",
    ["libssl3", "3.0.11-1~deb12u2", "amd64", "ii ", "openssl", "3.0.11-1~deb12u2"].join(T),
    ["bash", "5.2.15-2+b2", "amd64", "ii ", "bash", "5.2.15-2+b2"].join(T),
    ["bsdutils", "1:2.38.1-5+deb12u1", "amd64", "ii ", "util-linux", "2.38.1-5+deb12u1"].join(T),
    "@@end",
  ].join("\n"),
);
const dir = mkdtempSync(join(tmpdir(), "garnetops-sbom-test-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe.skipIf(!existsSync(syftBin))("the host SBOM, read by syft", () => {
  it("is accepted as a syft-json SBOM with the same packages, purls and distribution", () => {
    const file = join(dir, "host.syft.json");
    writeFileSync(
      file,
      JSON.stringify(buildHostSbom({ name: "web-01", os: report.os, packages: report.packages })),
    );
    const out = spawnSync(syftBin, ["convert", file, "-o", "syft-json", "-q"], {
      encoding: "utf8",
      env: { PATH: process.env.PATH, HOME: dir, SYFT_CHECK_FOR_APP_UPDATE: "false" },
    });
    expect(out.status, out.stderr).toBe(0);
    const converted = JSON.parse(out.stdout) as {
      artifacts: {
        name: string;
        version: string;
        purl: string;
        type: string;
        metadata: { source?: string };
      }[];
      distro: { id: string; versionID: string };
    };
    expect(converted.distro).toMatchObject({ id: "debian", versionID: "12" });
    const byName = new Map(converted.artifacts.map((a) => [a.name, a]));
    expect([...byName.keys()].sort()).toEqual(["bash", "bsdutils", "libssl3"]);
    expect(byName.get("libssl3")).toMatchObject({
      type: "deb",
      version: "3.0.11-1~deb12u2",
      purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl",
    });
    expect(byName.get("libssl3")?.metadata.source).toBe("openssl");
    expect(byName.get("bsdutils")?.version).toBe("1:2.38.1-5+deb12u1");
  });
});

describe.skipIf(!existsSync(grypeBin) || !haveDb)("the host SBOM, matched by grype", () => {
  it("finds known vulnerabilities in a Debian 12 package by its source package", async () => {
    const { scanTarget, parseReport } = await import("./grype.ts");
    const file = join(dir, "grype.syft.json");
    writeFileSync(
      file,
      JSON.stringify(buildHostSbom({ name: "web-01", os: report.os, packages: report.packages })),
    );
    const parsed = parseReport(await scanTarget(`sbom:${file}`, dir), "host_1");
    const libssl = [...parsed.findings.values()].filter((f) => f.packageName === "libssl3");
    expect(libssl.length).toBeGreaterThan(0);
    expect(libssl.every((f) => f.packageType === "deb")).toBe(true);
  }, 120_000);
});
