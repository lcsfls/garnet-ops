import { describe, expect, it } from "vitest";
import {
  EXPOSED_FILE_KINDS,
  EXPOSED_FILE_PROBES,
  EXPOSED_FILE_SEVERITY,
  type ExposedFileKind,
  provesExposedFile,
} from "./exposed-files.ts";
import { evaluatePassive, type PassiveSnapshot, unjudgedRules } from "./exposure.ts";

const text = (s: string) => new TextEncoder().encode(s);
const bytes = (...b: number[]) => new Uint8Array(b);

/** One real-looking body per kind; values are placeholders built here, never real credentials. */
const REAL: Record<ExposedFileKind, Uint8Array> = {
  envFile: text("APP_ENV=production\nDATABASE_URL=postgres://app:placeholder@db/app\n"),
  gitRepository: text("ref: refs/heads/main\n"),
  cloudCredentials: text("[default]\naws_access_key_id = placeholder\naws_secret_access_key = placeholder\n"),
  registryToken: text(`//registry.example.com/:_authToken=${"p".repeat(12)}\n`),
  htpasswd: text("admin:$apr1$abc$placeholderplaceholder\n"),
  aiAgentSettings: text('{"permissions":{"allow":["Bash(npm test)"]}}'),
  configBackup: text("<?php\ndefine( 'DB_NAME', 'wp' );\ndefine( 'DB_PASSWORD', 'placeholder' );\n"),
  sqlDump: text("-- MySQL dump 10.13  Distrib 8.0\n--\nCREATE TABLE `users` (\n"),
  archive: bytes(0x50, 0x4b, 0x03, 0x04, 0x14, 0x00),
  phpinfo: text("<!DOCTYPE html><html><head><title>PHP 8.3.4 - phpinfo()</title></head>"),
  serverStatus: text(
    "<html><head><title>Apache Status</title></head><body><h1>Apache Server Status for example.com</h1>",
  ),
  dsStore: bytes(0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31, 0x00),
};

describe("exposed files", () => {
  it("asks for at most 24 fixed paths, each of a known kind", () => {
    expect(EXPOSED_FILE_PROBES.length).toBeLessThanOrEqual(24);
    for (const p of EXPOSED_FILE_PROBES) {
      expect(p.path).toMatch(/^\/[A-Za-z0-9._~/-]+$/);
      expect(EXPOSED_FILE_KINDS).toContain(p.kind);
    }
    expect(new Set(EXPOSED_FILE_PROBES.map((p) => p.path)).size).toBe(EXPOSED_FILE_PROBES.length);
    expect(EXPOSED_FILE_SEVERITY.envFile).toBe("critical");
    expect(EXPOSED_FILE_SEVERITY.dsStore).toBe("low");
  });

  it("counts a file only when its content proves it", () => {
    for (const kind of EXPOSED_FILE_KINDS) {
      expect(provesExposedFile(kind, 200, REAL[kind]), kind).toBe(true);
    }
  });

  it("does not count a soft 404, another status, an empty body or the wrong content", () => {
    const page = text(
      "<!doctype html><html><head><title>Not found</title></head><body>APP_ENV=x\nA_B=y</body></html>",
    );
    for (const kind of EXPOSED_FILE_KINDS) {
      expect(provesExposedFile(kind, 200, page), kind).toBe(false);
      expect(provesExposedFile(kind, 404, REAL[kind]), kind).toBe(false);
      expect(provesExposedFile(kind, 301, REAL[kind]), kind).toBe(false);
      expect(provesExposedFile(kind, null, REAL[kind]), kind).toBe(false);
      expect(provesExposedFile(kind, 200, new Uint8Array()), kind).toBe(false);
    }
    expect(provesExposedFile("envFile", 200, text("ONLY_ONE=value\n"))).toBe(false);
    expect(provesExposedFile("sqlDump", 200, text("SELECT 1;"))).toBe(false);
    expect(provesExposedFile("archive", 200, text("PK but not a zip"))).toBe(false);
  });
});

describe("exposed files as website findings", () => {
  const base: PassiveSnapshot = {
    version: 1,
    takenAt: "2026-11-11T00:00:00.000Z",
    kind: "domain",
    name: "site.example.com",
    addresses: ["192.0.2.10"],
    nonPublic: [],
    dns: null,
    ptr: [],
    tls: [],
    http: null,
    plain: null,
    resolves: true,
    httpsOpen: true,
  };
  const now = new Date("2026-11-11T00:00:00Z");

  it("become one finding per path with the kind's severity", () => {
    const findings = evaluatePassive(
      {
        ...base,
        exposedFiles: {
          error: null,
          checked: 24,
          failed: 0,
          found: [
            { path: "/.env", kind: "envFile" },
            { path: "/.DS_Store", kind: "dsStore" },
          ],
        },
      },
      now,
    ).filter((f) => f.rule === "exposedFile");
    expect(findings).toEqual([
      {
        rule: "exposedFile",
        subject: "/.env",
        severity: "critical",
        stage: "passive",
        params: { path: "/.env", kind: "envFile" },
      },
      {
        rule: "exposedFile",
        subject: "/.DS_Store",
        severity: "low",
        stage: "passive",
        params: { path: "/.DS_Store", kind: "dsStore" },
      },
    ]);
  });

  it("are left as they are when not every answer came or the proof is gone, and judged when the check is off", () => {
    const failed = { error: null, checked: 24, failed: 3, found: [] };
    expect(unjudgedRules({ ...base, exposedFiles: failed })).toContain("exposedFile");
    expect(
      unjudgedRules({ ...base, exposedFiles: { ...failed, failed: 0, error: "notVerified" } }),
    ).toContain("exposedFile");
    expect(unjudgedRules({ ...base, exposedFiles: { ...failed, failed: 0 } })).not.toContain("exposedFile");
    // Switched off: no snapshot, findings resolve (the API also resolves them at once).
    expect(unjudgedRules(base)).not.toContain("exposedFile");
  });
});
