import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CODE_VIEW_LIMITS } from "@garnetops/core/code-view";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { readCloneText, readDeclarations, searchUsages } from "./code-read.ts";

describe("reading code from a clone", () => {
  let base: string;
  let root: string;
  const write = (path: string, text: string | Uint8Array) => {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), text);
  };

  beforeAll(() => {
    base = mkdtempSync(join(tmpdir(), "garnetops-code-read-"));
    root = join(base, "clone");
    mkdirSync(root);
    writeFileSync(join(base, "outside.txt"), 'import x from "lodash";\n');
    write(
      "package.json",
      '{\n  "name": "app",\n  "dependencies": {\n    "lodash": "^4.17.15",\n    "lodash.merge": "1.0.0"\n  }\n}\n',
    );
    write(
      "web/package-lock.json",
      '{\n  "packages": {\n    "node_modules/lodash": {\n      "version": "4.17.15"\n    }\n  }\n}\n',
    );
    write("src/a.ts", 'import _ from "lodash";\nexport const x = _.merge({}, {});\n');
    write("src/b.js", "const merge = require('lodash/merge');\n");
    write("src/c.ts", 'import x from "lodash-es";\n');
    write("node_modules/lodash/index.js", 'require("lodash");\n');
    write("src/binary.js", new Uint8Array([0x69, 0x6d, 0x00, 0x01]));
    write("src/big.js", `import _ from "lodash";\n${"x".repeat(CODE_VIEW_LIMITS.maxFileBytes)}`);
    symlinkSync(join(base, "outside.txt"), join(root, "src", "link.js"));
    symlinkSync(base, join(root, "up"));
  });
  afterAll(() => rmSync(base, { recursive: true, force: true }));

  it("reads regular text files inside the clone only", async () => {
    expect(await readCloneText(root, "src/a.ts")).toContain("lodash");
    expect(await readCloneText(root, "src/link.js")).toBeNull();
    expect(await readCloneText(root, "up/outside.txt")).toBeNull();
    expect(await readCloneText(root, "../outside.txt")).toBeNull();
    expect(await readCloneText(root, "src/binary.js")).toBeNull();
    expect(await readCloneText(root, "src/big.js")).toBeNull();
    expect(await readCloneText(root, "src/missing.ts")).toBeNull();
  });

  it("shows the declaring lines of manifests and lockfiles, with the grype-style leading slash cleaned", async () => {
    const out = await readDeclarations(root, "lodash", [
      { path: "package.json", role: "manifest" },
      { path: "/web/package-lock.json", role: "lockfile" },
      { path: "package.json", role: "manifest" },
      { path: "../outside.txt", role: "lockfile" },
    ]);
    expect(out.map((e) => [e.path, e.role, e.marks, e.language])).toEqual([
      ["package.json", "manifest", [4], "json"],
      ["web/package-lock.json", "lockfile", [3], "json"],
    ]);
  });

  it("finds usages in the project's own sources, never in node_modules, links or binaries", async () => {
    const found = await searchUsages(root, "npm", "lodash");
    expect(found.usages.map((u) => [u.path, u.marks])).toEqual([
      ["src/a.ts", [1]],
      ["src/b.js", [1]],
    ]);
    expect(found).toMatchObject({ usageCount: 2, usageFileCount: 2, search: { ran: true, stopped: null } });
    expect(found.usages[0]?.lines.map((l) => l.n)).toEqual([1, 2, 3]);
  });

  it("stops when the time is up, and does not search where the name says nothing", async () => {
    let t = 0;
    const slow = await searchUsages(root, "npm", "lodash", () => (t += CODE_VIEW_LIMITS.maxSearchMs));
    expect(slow.search.stopped).toBe("time");
    expect(await searchUsages(root, "php", "vendor/pkg")).toMatchObject({ search: { ran: false } });
  });
});
