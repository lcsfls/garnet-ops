#!/usr/bin/env node
import { execFileSync } from "node:child_process";
/**
 * Downloads pinned scanner binaries into .tools/ and verifies them against
 * SHA-256 checksums that are pinned in this file (not fetched at run time).
 *
 * To upgrade: change the version, copy the new hashes from the release's
 * checksums file after verifying its sigstore bundle, and record the change
 * in docs/COMPONENTS.md.
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { arch, platform } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const tools = join(root, ".tools");

const TOOLS = [
  {
    name: "grype",
    version: "0.120.1",
    sha256: {
      "linux-x64": "0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d",
      "linux-arm64": "29f47391dc283aa79fcc38e65224cd61f64dec0ecfd0db7074128ebf8ff23514",
      "darwin-x64": "5313004ccbc524c8757521dc3913f1edf4309f56bef06a2fb2d0c0eeade7cc62",
      "darwin-arm64": "cf97957fa467d25575ec2cc3228289f391ea51cf88b9cffc5f83dc03d4cbc732",
      "win32-x64": "32e3c811f31822d17592908bafdc6288aaaca3d52583c479167a8dc8399ed65d",
    },
  },
  {
    // Builds the SBOM (package inventory) of every scan; grype then matches that SBOM.
    name: "syft",
    version: "1.55.0",
    sha256: {
      "linux-x64": "bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d",
      "linux-arm64": "929bd163db2d7cd2255d3bcb8967208079813d7b46b0c952f7b794d8e2c7d304",
      "darwin-x64": "e2e5831cbabaec9a36fe65c34755c1113982c842a685edce3ce0b54a0ded8003",
      "darwin-arm64": "1217c258bd5eb91ef3189cf22a82e02f9cac07e4ce934350f428e93aff674625",
      "win32-x64": "ada4c9b93af575f479ce80fce6629897272a2d41f300a14bc49bace020767ca2",
    },
  },
];

const key = `${platform()}-${arch()}`;
const goOs = { linux: "linux", darwin: "darwin", win32: "windows" }[platform()];
const goArch = { x64: "amd64", arm64: "arm64" }[arch()];
const ext = platform() === "win32" ? "zip" : "tar.gz";

async function install(tool) {
  const expected = tool.sha256[key];
  if (!goOs || !goArch || !expected) {
    console.error(`No pinned ${tool.name} build for ${key}`);
    process.exit(1);
  }
  const file = `${tool.name}_${tool.version}_${goOs}_${goArch}.${ext}`;
  const url = `https://github.com/anchore/${tool.name}/releases/download/v${tool.version}/${file}`;
  const dest = join(tools, tool.name);
  const binary = join(dest, platform() === "win32" ? `${tool.name}.exe` : tool.name);
  const marker = join(dest, "VERSION");

  if (existsSync(binary) && existsSync(marker) && readFileSync(marker, "utf8").trim() === tool.version) {
    console.log(`${tool.name} ${tool.version} already present`);
    return binary;
  }
  console.log(`downloading ${url}`);
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) throw new Error(`Download failed: HTTP ${res.status}`);
  const data = Buffer.from(await res.arrayBuffer());
  const actual = createHash("sha256").update(data).digest("hex");
  if (actual !== expected) {
    console.error(`Checksum mismatch for ${file}\n  expected ${expected}\n  actual   ${actual}`);
    process.exit(1);
  }
  rmSync(dest, { recursive: true, force: true });
  mkdirSync(dest, { recursive: true });
  const archive = join(dest, file);
  writeFileSync(archive, data);
  // On Windows use the system bsdtar explicitly: a GNU tar from Git Bash on PATH reads
  // "C:" as a remote host and cannot open zip files.
  const tar =
    platform() === "win32" ? join(process.env.SystemRoot ?? "C:\\Windows", "System32", "tar.exe") : "tar";
  execFileSync(tar, ["-xf", archive, "-C", dest], { stdio: "inherit" });
  rmSync(archive);
  writeFileSync(marker, `${tool.version}\n`);
  console.log(`${tool.name} ${tool.version} installed in ${dest} (sha256 verified)`);
  return binary;
}

const binaries = {};
for (const tool of TOOLS) binaries[tool.name] = await install(tool);

if (process.argv.includes("--with-db")) {
  // Development only: fetches Anchore's published database. Production builds its own
  // database with vunnel and grype-db (ROADMAP Phase 1).
  const env = {
    ...process.env,
    GRYPE_DB_CACHE_DIR: join(tools, "grype-db"),
    GRYPE_CHECK_FOR_APP_UPDATE: "false",
  };
  execFileSync(binaries.grype, ["db", "update"], { stdio: "inherit", env });
}
