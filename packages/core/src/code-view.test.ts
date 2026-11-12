import { describe, expect, it } from "vitest";
import {
  CODE_VIEW_LIMITS,
  cleanLine,
  cleanRepoPath,
  declarationLines,
  ecosystemOf,
  excerpt,
  languageOf,
  looksLikeText,
  usagePattern,
} from "./code-view.ts";

describe("where a package is declared", () => {
  const manifest = `{
  "dependencies": {
    "lodash": "^4.17.20",
    "lodash.merge": "^4.6.2",
    "@scope/lodash": "1.0.0"
  }
}`;

  it("finds the package as a whole name, not as part of a longer one", () => {
    expect(declarationLines(manifest, "lodash")).toEqual([3]);
    expect(declarationLines(manifest, "lodash.merge")).toEqual([4]);
    expect(declarationLines(manifest, "@scope/lodash")).toEqual([5]);
    expect(declarationLines("requests==2.31.0\nrequests-toolbelt==1.0", "requests")).toEqual([1]);
    expect(declarationLines('[[package]]\nname = "serde"\nversion = "1.0.1"', "serde")).toEqual([2]);
    // Lockfiles: npm's node_modules/ keys, yarn's name@range, pnpm's /name@version; a scoped namesake is not it.
    expect(
      declarationLines('    "node_modules/lodash": {\n    "node_modules/@x/lodash": {', "lodash"),
    ).toEqual([1]);
    expect(declarationLines("lodash@^4.17.15:\n  version", "lodash")).toEqual([1]);
    expect(declarationLines("  /lodash@4.17.15:\n  /lodash-es@4.17.21:", "lodash")).toEqual([1]);
  });

  it("stops after a fixed number of places", () => {
    const many = Array.from({ length: 50 }, () => '"lodash": "1"').join("\n");
    expect(declarationLines(many, "lodash")).toHaveLength(CODE_VIEW_LIMITS.maxDeclarationMatches);
  });

  it("shows windows around the places, merged where they touch", () => {
    const text = Array.from({ length: 30 }, (_, i) => `line ${i + 1}`).join("\n");
    const lines = excerpt(text, [5, 8, 25], 2);
    expect(lines.map((l) => l.n)).toEqual([3, 4, 5, 6, 7, 8, 9, 10, 23, 24, 25, 26, 27]);
    expect(excerpt("a\nb", [1], 5).map((l) => l.text)).toEqual(["a", "b"]);
  });
});

describe("where the code uses it", () => {
  const hits = (ecosystem: Parameters<typeof usagePattern>[0], name: string, lines: string[]) => {
    const re = usagePattern(ecosystem, name);
    return lines.filter((l) => re?.test(l));
  };

  it("npm: import, require, dynamic import and subpaths, not namesakes", () => {
    expect(
      hits("npm", "lodash", [
        'import _ from "lodash";',
        "const merge = require('lodash/merge');",
        "await import(`lodash`)",
        'import "lodash";',
        'import x from "lodash-es";',
        'const s = "lodash";',
        "// uses lodash for things",
      ]),
    ).toEqual([
      'import _ from "lodash";',
      "const merge = require('lodash/merge');",
      "await import(`lodash`)",
      'import "lodash";',
    ]);
    expect(hits("npm", "@scope/pkg", ['import { a } from "@scope/pkg/sub";'])).toHaveLength(1);
  });

  it("python, go and rust by their own way of naming a package", () => {
    expect(
      hits("python", "PyJWT", ["import pyjwt", "from pyjwt.algorithms import x", "import os, pyjwt"]),
    ).toHaveLength(3);
    expect(hits("python", "requests", ["import requests_toolbelt", "x = requests.get()"])).toEqual([]);
    expect(hits("go", "golang.org/x/net", ['\t"golang.org/x/net/http2"', '"golang.org/x/network"'])).toEqual([
      '\t"golang.org/x/net/http2"',
    ]);
    expect(
      hits("rust", "serde-json", [
        "use serde_json::Value;",
        "let v = serde_json::from_str(x);",
        "use other::serde_json_x;",
      ]),
    ).toHaveLength(2);
  });

  it("has no pattern where the name does not tell, or the name is odd", () => {
    expect(usagePattern("php", "vendor/package")).toBeNull();
    expect(usagePattern("other", "x")).toBeNull();
    expect(usagePattern("npm", "bad name with spaces")).toBeNull();
    expect(usagePattern("npm", "a(b)+")).toBeNull();
  });

  it("maps grype's package types", () => {
    expect(ecosystemOf("npm")).toBe("npm");
    expect(ecosystemOf("go-module")).toBe("go");
    expect(ecosystemOf("rust-crate")).toBe("rust");
    expect(ecosystemOf("java-archive")).toBe("other");
  });
});

describe("text as it is shown", () => {
  it("chooses the language by name, never by content", () => {
    expect(languageOf("src/app.tsx")).toBe("typescript");
    expect(languageOf("package-lock.json")).toBe("json");
    expect(languageOf("Cargo.toml")).toBe("ini");
    expect(languageOf("yarn.lock")).toBeNull();
    expect(languageOf("deploy/Dockerfile")).toBe("dockerfile");
    expect(languageOf("README")).toBeNull();
  });

  it("removes control and bidirectional characters, keeps tabs, cuts long lines", () => {
    expect(cleanLine("\tok‮\u0007x").text).toBe("\tokx");
    const long = cleanLine("x".repeat(CODE_VIEW_LIMITS.maxLineLength + 5));
    expect(long).toEqual({ text: "x".repeat(CODE_VIEW_LIMITS.maxLineLength), cut: true });
  });

  it("tells text from binary and keeps paths inside the repository", () => {
    expect(looksLikeText(new TextEncoder().encode("hello"))).toBe(true);
    expect(looksLikeText(new Uint8Array([0x89, 0x50, 0x00]))).toBe(false);
    expect(cleanRepoPath("/package-lock.json")).toBe("package-lock.json");
    expect(cleanRepoPath("./a/b.ts")).toBe("a/b.ts");
    expect(cleanRepoPath("a/../../etc/passwd")).toBeNull();
    expect(cleanRepoPath("")).toBeNull();
  });
});
