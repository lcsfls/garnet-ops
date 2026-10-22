import { describe, expect, test } from "vitest";
import {
  bumpSpec,
  editManifest,
  isSafePackageName,
  listDependencies,
  MAX_MANIFEST_BYTES,
  type ManifestKind,
  manifestKindOfPath,
  manifestPathFor,
  normalizeName,
  safeRepoPath,
} from "./manifests.ts";

function edit(kind: ManifestKind, text: string, name: string, target: string) {
  return editManifest(kind, text, { name, target });
}

function ok(result: ReturnType<typeof editManifest>) {
  if (!result.ok) throw new Error(`refused: ${result.reason}`);
  return result;
}

function refused(result: ReturnType<typeof editManifest>) {
  if (result.ok) throw new Error("expected a refusal");
  return result.reason;
}

describe("paths", () => {
  test("manifest kinds by file name", () => {
    expect(manifestKindOfPath("package.json")).toBe("npm");
    expect(manifestKindOfPath("apps/web/package.json")).toBe("npm");
    expect(manifestKindOfPath("composer.json")).toBe("composer");
    expect(manifestKindOfPath("go.mod")).toBe("go");
    expect(manifestKindOfPath("rust/Cargo.toml")).toBe("cargo");
    expect(manifestKindOfPath("requirements.txt")).toBe("pypi");
    expect(manifestKindOfPath("deploy/requirements-dev.txt")).toBe("pypi");
    expect(manifestKindOfPath("requirements/base.txt")).toBeNull();
    expect(manifestKindOfPath("pyproject.toml")).toBeNull();
    expect(manifestKindOfPath("package.json.bak")).toBeNull();
    expect(manifestKindOfPath("constructor")).toBeNull();
  });

  test("a lockfile points to the manifest next to it", () => {
    expect(manifestPathFor("npm", "/package-lock.json")).toBe("package.json");
    expect(manifestPathFor("npm", "/web/yarn.lock")).toBe("web/package.json");
    expect(manifestPathFor("npm", "/web/pnpm-lock.yaml")).toBe("web/package.json");
    expect(manifestPathFor("composer", "/app/composer.lock")).toBe("app/composer.json");
    expect(manifestPathFor("go", "/go.sum")).toBe("go.mod");
    expect(manifestPathFor("cargo", "/crates/x/Cargo.lock")).toBe("crates/x/Cargo.toml");
    expect(manifestPathFor("pypi", "/requirements.txt")).toBe("requirements.txt");
  });

  test("nothing GarnetOps cannot edit, nothing outside the repository", () => {
    expect(manifestPathFor("npm", "/node_modules/lodash/package.json")).toBeNull();
    expect(manifestPathFor("composer", "/vendor/x/composer.json")).toBeNull();
    expect(manifestPathFor("pypi", "/poetry.lock")).toBeNull();
    expect(manifestPathFor("pypi", "/usr/lib/python3/site-packages/x/METADATA")).toBeNull();
    expect(manifestPathFor("npm", "/../package-lock.json")).toBeNull();
    expect(manifestPathFor("npm", "/a/../package-lock.json")).toBeNull();
    expect(manifestPathFor("npm", "/a\\package-lock.json")).toBeNull();
    expect(manifestPathFor("npm", "/a/\u0000/package-lock.json")).toBeNull();
    expect(manifestPathFor("npm", `/${"a/".repeat(300)}package-lock.json`)).toBeNull();
    expect(manifestPathFor("go", "/main")).toBeNull();
  });

  test("safeRepoPath", () => {
    expect(safeRepoPath("/a/b.txt")).toBe("a/b.txt");
    expect(safeRepoPath("a//b")).toBeNull();
    expect(safeRepoPath("./a")).toBeNull();
    expect(safeRepoPath("")).toBeNull();
  });

  test("names and package names", () => {
    expect(normalizeName("pypi", "Django_Rest.Framework")).toBe("django-rest-framework");
    expect(normalizeName("cargo", "Serde_JSON")).toBe("serde-json");
    expect(normalizeName("composer", "Monolog/Monolog")).toBe("monolog/monolog");
    expect(isSafePackageName("@scope/pkg.js")).toBe(true);
    expect(isSafePackageName("github.com/foo/bar")).toBe(true);
    for (const bad of ["", "-rf", "a b", "a;b", "a\nb", "`x`", "../etc", "a$(x)", "a'b"]) {
      expect(isSafePackageName(bad), bad).toBe(false);
    }
  });
});

describe("bumpSpec", () => {
  test("keeps the operator", () => {
    expect(bumpSpec("npm", "^4.17.20", "4.17.21")).toEqual({ ok: true, spec: "^4.17.21" });
    expect(bumpSpec("npm", "~4.17.20", "4.17.21")).toEqual({ ok: true, spec: "~4.17.21" });
    expect(bumpSpec("npm", "4.17.20", "4.17.21")).toEqual({ ok: true, spec: "4.17.21" });
    expect(bumpSpec("npm", "=4.17.20", "4.17.21")).toEqual({ ok: true, spec: "=4.17.21" });
    expect(bumpSpec("npm", ">=4.17.20", "4.17.21")).toEqual({ ok: true, spec: ">=4.17.21" });
    expect(bumpSpec("npm", "v1.0.0", "1.0.1")).toEqual({ ok: true, spec: "1.0.1" });
    expect(bumpSpec("cargo", "1.0.100", "1.0.101")).toEqual({ ok: true, spec: "1.0.101" });
    expect(bumpSpec("composer", "^2.0", "2.5.1")).toEqual({ ok: true, spec: "^2.5.1" });
    expect(bumpSpec("pypi", "==2.25.0", "2.31.0")).toEqual({ ok: true, spec: "==2.31.0" });
    expect(bumpSpec("go", "v1.4.0", "1.4.2")).toEqual({ ok: true, spec: "v1.4.2" });
  });

  test("a requirement that already allows the target needs only a lockfile update", () => {
    expect(bumpSpec("npm", "^4.17.21", "4.17.21")).toEqual({ ok: false, reason: "already-satisfied" });
    expect(bumpSpec("npm", "^5.0.0", "4.17.21")).toEqual({ ok: false, reason: "already-satisfied" });
    expect(bumpSpec("pypi", "==2.31.0", "2.31.0")).toEqual({ ok: false, reason: "already-satisfied" });
    expect(bumpSpec("go", "v1.4.2", "1.4.2")).toEqual({ ok: false, reason: "already-satisfied" });
  });

  test("complex ranges and non-registry sources are refused", () => {
    for (const spec of [
      ">=1.0.0 <2.0.0",
      "1.x",
      "*",
      "latest",
      "^1.0.0 || ^2.0.0",
      "",
      "1.0.0 - 2.0.0",
      "<2.0.0",
    ]) {
      expect(bumpSpec("npm", spec, "1.5.0"), spec).toMatchObject({ ok: false, reason: "complex-range" });
    }
    for (const spec of [
      "git+https://example.com/x.git",
      "github:user/repo",
      "user/repo",
      "file:../x",
      "workspace:*",
      "npm:other@1.0.0",
      "https://example.com/x.tgz",
      "link:../x",
    ]) {
      expect(bumpSpec("npm", spec, "1.5.0"), spec).toMatchObject({ ok: false, reason: "unsupported-source" });
    }
    expect(bumpSpec("composer", "dev-main", "1.5.0")).toMatchObject({ reason: "unsupported-source" });
    expect(bumpSpec("composer", "1.x-dev", "1.5.0")).toMatchObject({ reason: "unsupported-source" });
    expect(bumpSpec("pypi", ">=2.0", "2.31.0")).toMatchObject({ reason: "complex-range" });
    expect(bumpSpec("pypi", "==2.*", "2.31.0")).toMatchObject({ reason: "complex-range" });
    expect(bumpSpec("pypi", "~=2.0", "2.31.0")).toMatchObject({ reason: "complex-range" });
  });

  test("a Go major release is a different import path and is not edited", () => {
    expect(bumpSpec("go", "v1.4.0", "2.0.1")).toEqual({ ok: false, reason: "major-change" });
  });

  test("the target must be a plain release", () => {
    for (const target of ["", "1.2.3-rc.1", "^1.2.3", "1.2.3; rm -rf /", "latest", "1.2.3\n", `"1.0"`]) {
      expect(bumpSpec("npm", "^1.0.0", target), target).toEqual({ ok: false, reason: "bad-target" });
    }
    expect(bumpSpec("pypi", "==1.0", "1.1rc1")).toEqual({ ok: false, reason: "bad-target" });
    expect(bumpSpec("go", "v1.0.0", "1.1.0-rc.1")).toEqual({ ok: false, reason: "bad-target" });
  });

  test("Go keeps +incompatible", () => {
    expect(bumpSpec("go", "v2.1.0+incompatible", "2.1.5")).toEqual({ ok: true, spec: "v2.1.5+incompatible" });
  });
});

describe("package.json", () => {
  const manifest = `{
  "name": "demo",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.20",
    "express": "4.18.1"
  },
  "devDependencies": {
    "lodash": "~4.17.0",
    "typescript": "^5.0.0"
  },
  "peerDependencies": { "react": ">=17" }
}
`;

  test("changes only the requirement and keeps the operator and every other byte", () => {
    const result = ok(edit("npm", manifest, "express", "4.18.2"));
    expect(result.text).toBe(manifest.replace('"4.18.1"', '"4.18.2"'));
    expect(result.changes).toHaveLength(1);
    expect(result.changes[0]).toMatchObject({ section: "dependencies", from: "4.18.1", to: "4.18.2" });
  });

  test("bumps every section the package is declared in", () => {
    const result = ok(edit("npm", manifest, "lodash", "4.17.21"));
    expect(result.text).toBe(manifest.replace('"^4.17.20"', '"^4.17.21"').replace('"~4.17.0"', '"~4.17.21"'));
    expect(result.changes.map((c) => c.section).sort()).toEqual(["dependencies", "devDependencies"]);
  });

  test("keeps CRLF line endings and a byte order mark", () => {
    const crlf = `﻿${manifest.replaceAll("\n", "\r\n")}`;
    const result = ok(edit("npm", crlf, "express", "4.18.2"));
    expect(result.text).toBe(crlf.replace('"4.18.1"', '"4.18.2"'));
    expect(result.text.startsWith("﻿")).toBe(true);
    expect(result.text.includes("\r\n")).toBe(true);
  });

  test("works on minified one-line files and tabs", () => {
    const min = '{"dependencies":{"a":"1.0.0","b":"^2.0.0"}}';
    expect(ok(edit("npm", min, "b", "2.0.5")).text).toBe('{"dependencies":{"a":"1.0.0","b":"^2.0.5"}}');
    const tabbed = '{\n\t"dependencies": {\n\t\t"a" :\t"1.0.0"\n\t}\n}';
    expect(ok(edit("npm", tabbed, "a", "1.0.1")).text).toBe(tabbed.replace("1.0.0", "1.0.1"));
  });

  test("scoped packages and escaped keys", () => {
    const text = '{"dependencies":{"@scope/pkg":"^1.0.0","with\\u002descape":"1.0.0"}}';
    expect(ok(edit("npm", text, "@scope/pkg", "1.2.0")).text).toContain('"@scope/pkg":"^1.2.0"');
    expect(ok(edit("npm", text, "with-escape", "1.0.1")).text).toContain('"with\\u002descape":"1.0.1"');
  });

  test("refuses what it cannot edit safely", () => {
    expect(refused(edit("npm", manifest, "react", "18.2.0"))).toBe("not-found"); // peer dependencies are not touched
    expect(refused(edit("npm", manifest, "left-pad", "1.3.0"))).toBe("not-found");
    expect(refused(edit("npm", manifest, "express", "4.18.1"))).toBe("already-satisfied");
    expect(refused(edit("npm", '{"dependencies":{"a":">=1 <3"}}', "a", "2.0.0"))).toBe("complex-range");
    expect(refused(edit("npm", '{"dependencies":{"a":"git+https://example.com/a.git"}}', "a", "2.0.0"))).toBe(
      "unsupported-source",
    );
    expect(refused(edit("npm", '{"dependencies":{"a":{"v":1}}}', "a", "2.0.0"))).toBe("unsupported-source");
  });

  test("all or nothing: one occurrence that cannot be edited refuses the whole change", () => {
    const text = '{"dependencies":{"a":"^1.0.0"},"devDependencies":{"a":"git+https://example.com/a.git"}}';
    expect(refused(edit("npm", text, "a", "1.5.0"))).toBe("unsupported-source");
  });

  test("duplicate keys are ambiguous", () => {
    expect(refused(edit("npm", '{"dependencies":{"a":"1.0.0","a":"2.0.0"}}', "a", "3.0.0"))).toBe(
      "ambiguous",
    );
    expect(
      refused(edit("npm", '{"dependencies":{"a":"1.0.0"},"dependencies":{"a":"2.0.0"}}', "a", "3.0.0")),
    ).toBe("ambiguous");
  });

  test("invalid JSON is refused: comments, trailing commas, single quotes, truncation, garbage", () => {
    for (const bad of [
      '{"dependencies":{"a":"1.0.0"}} // c',
      '{"dependencies":{"a":"1.0.0",}}',
      "{'dependencies':{'a':'1.0.0'}}",
      '{"dependencies":{"a":"1.0.0"}',
      '{"dependencies":{"a":"1.0.0\n"}}',
      '{"dependencies":{"a":"\\x"}}',
      '{"dependencies":{"a":"1.0.0"}}}',
      "[]",
      "",
      "null",
      "{",
      '{"a":"\\ud800"}garbage',
    ]) {
      expect(refused(edit("npm", bad, "a", "9.0.0")), bad).toBe("invalid");
    }
  });

  test("deep nesting and huge files are bounded", () => {
    const deep = `{"x":${"[".repeat(5000)}${"]".repeat(5000)},"dependencies":{"a":"1.0.0"}}`;
    expect(refused(edit("npm", deep, "a", "1.0.1"))).toBe("invalid");
    const huge = `{"dependencies":{"a":"1.0.0"},"pad":"${"x".repeat(MAX_MANIFEST_BYTES)}"}`;
    expect(refused(edit("npm", huge, "a", "1.0.1"))).toBe("too-large");
    expect(listDependencies("npm", huge)).toBeNull();
  });

  test("a NUL byte is refused", () => {
    expect(refused(edit("npm", `{"dependencies":{"a":"1.0.0"}}\u0000`, "a", "1.0.1"))).toBe("invalid");
  });

  test("lists the dependencies with section and development flag", () => {
    const deps = listDependencies("npm", manifest) ?? [];
    expect(deps.map((d) => [d.name, d.section, d.spec, d.dev])).toEqual([
      ["lodash", "dependencies", "^4.17.20", false],
      ["express", "dependencies", "4.18.1", false],
      ["lodash", "devDependencies", "~4.17.0", true],
      ["typescript", "devDependencies", "^5.0.0", true],
    ]);
  });

  test("an odd __proto__ key is just a key", () => {
    const text = '{"__proto__":{"x":1},"dependencies":{"__proto__":"1.0.0","a":"1.0.0"}}';
    expect(ok(edit("npm", text, "a", "1.0.1")).text).toContain('"a":"1.0.1"');
  });
});

describe("composer.json", () => {
  const manifest = `{
    "require": {
        "php": "^8.1",
        "ext-json": "*",
        "Monolog/Monolog": "^2.8",
        "symfony/console": "5.4.2"
    },
    "require-dev": { "phpunit/phpunit": "^9.5" }
}`;
  test("bumps by the lowercase package name and ignores platform requirements", () => {
    const result = ok(edit("composer", manifest, "monolog/monolog", "2.9.1"));
    expect(result.text).toBe(manifest.replace('"^2.8"', '"^2.9.1"'));
    expect(refused(edit("composer", manifest, "php", "8.2.0"))).toBe("not-found");
    expect(refused(edit("composer", manifest, "ext-json", "9.9.9"))).toBe("not-found");
  });
  test("lists and flags development packages", () => {
    const deps = listDependencies("composer", manifest) ?? [];
    expect(deps.map((d) => d.name)).toEqual(["Monolog/Monolog", "symfony/console", "phpunit/phpunit"]);
    expect(deps.find((d) => d.name === "phpunit/phpunit")?.dev).toBe(true);
  });
  test("branches and aliases are refused", () => {
    expect(refused(edit("composer", '{"require":{"a/b":"dev-main"}}', "a/b", "1.0.0"))).toBe(
      "unsupported-source",
    );
    expect(refused(edit("composer", '{"require":{"a/b":"^1.0 || ^2.0"}}', "a/b", "2.0.1"))).toBe(
      "complex-range",
    );
  });
});

describe("requirements.txt", () => {
  const manifest = [
    "# pinned by pip-compile",
    "--index-url https://pypi.example.com/simple",
    "-r base.txt",
    "requests==2.25.0  # HTTP",
    "Django_Rest.Framework == 3.12.0 ; python_version >= '3.8'",
    "urllib3[secure]==1.26.5",
    "flask>=2.0",
    "numpy",
    "git+https://example.com/x.git#egg=x",
    "",
  ].join("\n");

  test("changes only the pinned version", () => {
    const result = ok(edit("pypi", manifest, "requests", "2.31.0"));
    expect(result.text).toBe(manifest.replace("requests==2.25.0", "requests==2.31.0"));
  });

  test("matches names the way Python does and keeps extras and markers", () => {
    const result = ok(edit("pypi", manifest, "django-rest-framework", "3.14.0"));
    expect(result.text).toContain("Django_Rest.Framework ==3.14.0 ; python_version >= '3.8'");
    expect(ok(edit("pypi", manifest, "urllib3", "1.26.18")).text).toContain("urllib3[secure]==1.26.18");
  });

  test("keeps CRLF", () => {
    const crlf = manifest.replaceAll("\n", "\r\n");
    expect(ok(edit("pypi", crlf, "requests", "2.31.0")).text).toBe(
      crlf.replace("requests==2.25.0", "requests==2.31.0"),
    );
  });

  test("ranges and unpinned lines are refused", () => {
    expect(refused(edit("pypi", manifest, "flask", "2.3.0"))).toBe("complex-range");
    expect(refused(edit("pypi", manifest, "numpy", "1.26.0"))).toBe("complex-range");
    expect(refused(edit("pypi", manifest, "x", "1.0.0"))).toBe("not-found");
  });

  test("hash-pinned requirements are refused", () => {
    const hashed = "requests==2.25.0 \\\n    --hash=sha256:abcdef\n";
    expect(refused(edit("pypi", hashed, "requests", "2.31.0"))).toBe("hashes");
    expect(refused(edit("pypi", "requests==2.25.0 --hash=sha256:abc\n", "requests", "2.31.0"))).toBe(
      "hashes",
    );
  });

  test("the same package twice is ambiguous", () => {
    expect(refused(edit("pypi", "a==1.0\na==2.0\n", "a", "3.0"))).toBe("ambiguous");
  });

  test("a binary file is refused", () => {
    expect(refused(edit("pypi", "a==1.0\u0000\n", "a", "2.0"))).toBe("invalid");
  });

  test("lists pins and ranges alike", () => {
    const deps = listDependencies("pypi", manifest) ?? [];
    expect(deps.map((d) => [d.name, d.spec])).toEqual([
      ["requests", "==2.25.0"],
      ["Django_Rest.Framework", "== 3.12.0"],
      ["urllib3", "==1.26.5"],
      ["flask", ">=2.0"],
      ["numpy", ""],
    ]);
  });
});

describe("go.mod", () => {
  const manifest = [
    "module example.com/app",
    "",
    "go 1.22",
    "",
    "require (",
    "\tgithub.com/gin-gonic/gin v1.9.0",
    "\tgolang.org/x/text v0.3.7 // indirect",
    "\tgithub.com/pkg/errors v0.9.1 // keep",
    ")",
    "",
    "require github.com/stretchr/testify v1.8.0",
    "replace github.com/old/mod => ../old",
    "",
  ].join("\n");

  test("changes only the version token in a block and in a single-line require", () => {
    expect(ok(edit("go", manifest, "github.com/gin-gonic/gin", "1.9.1")).text).toBe(
      manifest.replace("gin v1.9.0", "gin v1.9.1"),
    );
    expect(ok(edit("go", manifest, "github.com/stretchr/testify", "1.8.4")).text).toBe(
      manifest.replace("testify v1.8.0", "testify v1.8.4"),
    );
    expect(ok(edit("go", manifest, "github.com/pkg/errors", "0.9.2")).text).toContain(
      "github.com/pkg/errors v0.9.2 // keep",
    );
  });

  test("indirect requirements are not edited", () => {
    expect(refused(edit("go", manifest, "golang.org/x/text", "0.3.8"))).toBe("indirect");
    expect(
      (listDependencies("go", manifest) ?? []).find((d) => d.name === "golang.org/x/text")?.indirect,
    ).toBe(true);
  });

  test("a replace directive blocks the edit", () => {
    const text = `${manifest}replace github.com/gin-gonic/gin v1.9.0 => github.com/fork/gin v1.9.0\n`;
    expect(refused(edit("go", text, "github.com/gin-gonic/gin", "1.9.1"))).toBe("replaced");
    const block = "module m\nrequire a.example/b v1.0.0\nreplace (\n\ta.example/b => ../b\n)\n";
    expect(refused(edit("go", block, "a.example/b", "1.0.1"))).toBe("replaced");
  });

  test("a new major release needs a new import path", () => {
    expect(refused(edit("go", manifest, "github.com/gin-gonic/gin", "2.0.0"))).toBe("major-change");
  });

  test("a module that is not required, quoted paths and duplicates", () => {
    expect(refused(edit("go", manifest, "github.com/none/x", "1.0.0"))).toBe("not-found");
    expect(
      refused(edit("go", "require a.example/b v1.0.0\nrequire a.example/b v1.1.0\n", "a.example/b", "1.2.0")),
    ).toBe("ambiguous");
  });

  test("CRLF and tabs are kept", () => {
    const crlf = manifest.replaceAll("\n", "\r\n");
    expect(ok(edit("go", crlf, "github.com/gin-gonic/gin", "1.9.1")).text).toBe(
      crlf.replace("gin v1.9.0", "gin v1.9.1"),
    );
  });

  test("pseudo-versions can be moved to a release", () => {
    const text = "require a.example/b v0.0.0-20210101000000-abcdefabcdef\n";
    expect(refused(edit("go", text, "a.example/b", "1.2.0"))).toBe("major-change");
    const text2 = "require a.example/b v1.0.0-20210101000000-abcdefabcdef\n";
    expect(ok(edit("go", text2, "a.example/b", "1.2.0")).text).toBe("require a.example/b v1.2.0\n");
  });
});

describe("Cargo.toml", () => {
  const manifest = [
    "[package]",
    'name = "demo"',
    'version = "0.1.0"',
    "",
    "[dependencies]",
    'serde = "1.0.150"',
    'tokio = { version = "1.20.0", features = ["rt", "macros"] }',
    'regex = { git = "https://example.com/regex" }',
    'local = { path = "../local" }',
    "inherited.workspace = true",
    'renamed = { package = "real", version = "1.0.0" }',
    'multi = ["a", "b"]',
    "",
    "[dev-dependencies]",
    'serde = "~1.0.100" # tests',
    "",
    "[dependencies.openssl]",
    'version = "0.10.40"',
    'features = ["vendored"]',
    "",
    "[target.'cfg(unix)'.dependencies]",
    'libc = "0.2.100"',
    "",
    "[workspace.dependencies]",
    'anyhow = "1.0.60"',
    "",
    "[features]",
    'default = ["a"]',
    "",
  ].join("\n");

  test("a plain version string", () => {
    const result = ok(edit("cargo", manifest, "libc", "0.2.150"));
    expect(result.text).toBe(manifest.replace('libc = "0.2.100"', 'libc = "0.2.150"'));
  });

  test("an inline table keeps its other keys", () => {
    expect(ok(edit("cargo", manifest, "tokio", "1.25.1")).text).toBe(
      manifest.replace('version = "1.20.0"', 'version = "1.25.1"'),
    );
  });

  test("a table of its own", () => {
    expect(ok(edit("cargo", manifest, "openssl", "0.10.55")).text).toBe(
      manifest.replace('version = "0.10.40"', 'version = "0.10.55"'),
    );
  });

  test("every section the crate is declared in, comments kept", () => {
    const result = ok(edit("cargo", manifest, "serde", "1.0.190"));
    expect(result.text).toContain('serde = "1.0.190"');
    expect(result.text).toContain('serde = "~1.0.190" # tests');
    expect(result.changes).toHaveLength(2);
  });

  test("workspace dependency tables", () => {
    expect(ok(edit("cargo", manifest, "anyhow", "1.0.75")).text).toContain('anyhow = "1.0.75"');
  });

  test("git, path, workspace-inherited, renamed and multi-line values are refused", () => {
    expect(refused(edit("cargo", manifest, "regex", "1.9.0"))).toBe("unsupported-source");
    expect(refused(edit("cargo", manifest, "local", "1.0.0"))).toBe("unsupported-source");
    expect(refused(edit("cargo", manifest, "inherited", "1.0.0"))).toBe("unsupported-source");
    expect(refused(edit("cargo", manifest, "renamed", "1.0.1"))).toBe("unsupported-source");
    expect(refused(edit("cargo", manifest, "multi", "1.0.1"))).toBe("complex-range");
  });

  test("underscores and hyphens are the same crate", () => {
    const text = '[dependencies]\nserde-json = "1.0.0"\n';
    expect(ok(edit("cargo", text, "serde_json", "1.0.1")).text).toBe(
      '[dependencies]\nserde-json = "1.0.1"\n',
    );
  });

  test("a bracket inside a multi-line string or array is not a table header", () => {
    const text = [
      "[package]",
      'description = """',
      "[dependencies]",
      'serde = "0.0.1"',
      '"""',
      "keywords = [",
      "  # a comment with a [dependencies] header look-alike",
      '  "x",',
      "]",
      "[dependencies]",
      'serde = "1.0.0"',
      "",
    ].join("\n");
    expect(ok(edit("cargo", text, "serde", "1.0.5")).text).toBe(
      text.replace('serde = "1.0.0"', 'serde = "1.0.5"'),
    );
  });

  test("the same crate twice in a table is ambiguous", () => {
    expect(refused(edit("cargo", '[dependencies]\na = "1.0.0"\na = "1.1.0"\n', "a", "1.2.0"))).toBe(
      "ambiguous",
    );
    expect(
      refused(
        edit("cargo", '[dependencies]\na = "1.0.0"\n[dependencies.a]\nversion = "1.1.0"\n', "a", "1.2.0"),
      ),
    ).toBe("ambiguous");
  });

  test("CRLF is kept", () => {
    const crlf = manifest.replaceAll("\n", "\r\n");
    expect(ok(edit("cargo", crlf, "libc", "0.2.150")).text).toBe(
      crlf.replace('libc = "0.2.100"', 'libc = "0.2.150"'),
    );
  });

  test("escapes in a version string are refused", () => {
    expect(refused(edit("cargo", '[dependencies]\na = "1\\u002e0.0"\n', "a", "2.0.0"))).toBe("complex-range");
  });
});

describe("hostile input never throws and never edits outside the requirement", () => {
  const seeds: [ManifestKind, string, string][] = [
    ["npm", '{"dependencies":{"a":"^1.0.0","b":"2.0.0"},"devDependencies":{"a":"~1.0.0"}}\n', "a"],
    ["composer", '{"require":{"a/b":"^1.0","c/d":"2.0.0"}}\n', "a/b"],
    ["pypi", "a==1.0.0\nb>=2\n# c\nc==3.0.0 ; python_version<'3'\n", "a"],
    ["go", "module m\nrequire (\n\ta.example/b v1.0.0\n\tc.example/d v1.2.3 // indirect\n)\n", "a.example/b"],
    [
      "cargo",
      '[dependencies]\na = "1.0.0"\nb = { version = "2.0.0", features = ["x"] }\n[dependencies.c]\nversion = "3.0.0"\n',
      "a",
    ],
  ];

  /** Small deterministic generator so a failure can be reproduced. */
  function random(seed: number) {
    let state = seed >>> 0;
    return () => {
      state = (state * 1664525 + 1013904223) >>> 0;
      return state / 2 ** 32;
    };
  }

  const pieces = [
    "\r\n",
    "\n",
    "\t",
    " ",
    '"',
    "'",
    "{",
    "}",
    "[",
    "]",
    ",",
    ":",
    "=",
    "#",
    "//",
    "\\",
    "\u0000",
    "�",
    "﻿",
    "é",
    "\u{1F600}",
    "/*",
    "*/",
    '"""',
    "==",
    "^",
    "~",
    "1.0.0",
    "a",
  ];

  test("mutations: every outcome is a refusal or an edit confined to the requirement", () => {
    const rand = random(0xc0ffee);
    let edits = 0;
    let refusals = 0;
    for (let round = 0; round < 6000; round++) {
      const [kind, seed, name] = seeds[round % seeds.length] as [ManifestKind, string, string];
      let text = seed;
      const mutations = 1 + Math.floor(rand() * 4);
      for (let m = 0; m < mutations; m++) {
        const at = Math.floor(rand() * (text.length + 1));
        const roll = rand();
        if (roll < 0.4)
          text = text.slice(0, at) + (pieces[Math.floor(rand() * pieces.length)] as string) + text.slice(at);
        else if (roll < 0.6) text = text.slice(0, at) + text.slice(at + 1 + Math.floor(rand() * 8));
        else if (roll < 0.75) text = text.slice(0, at);
        else if (roll < 0.9) text = text.slice(0, at) + text.slice(Math.floor(rand() * text.length));
        else text = text + text.slice(0, at);
      }
      const result = editManifest(kind, text, { name, target: "9.9.9" });
      expect(() => listDependencies(kind, text)).not.toThrow();
      if (!result.ok) {
        refusals++;
        continue;
      }
      edits++;
      // Cut every replaced requirement out of the input and out of the output: what is left must be identical.
      const ordered = [...result.changes].sort((a, b) => a.start - b.start);
      const quoted = kind === "npm" || kind === "composer";
      let outsideInput = "";
      let outsideOutput = "";
      let inCursor = 0;
      for (const change of ordered) {
        expect(text.slice(change.start, change.end).replace(/^"|"$/g, "")).toBe(change.from);
        outsideInput += text.slice(inCursor, change.start);
        inCursor = change.end;
      }
      outsideInput += text.slice(inCursor);
      let delta = 0;
      let outCursor = 0;
      for (const change of ordered) {
        const newLength = (quoted ? 2 : 0) + change.to.length;
        const at = change.start + delta;
        outsideOutput += result.text.slice(outCursor, at);
        outCursor = at + newLength;
        delta += newLength - (change.end - change.start);
      }
      outsideOutput += result.text.slice(outCursor);
      expect(outsideOutput).toBe(outsideInput);
      // The edited manifest still reads, and shows the new requirement for that package.
      const after = listDependencies(kind, result.text);
      expect(after).not.toBeNull();
      expect(after?.some((d) => normalizeName(kind, d.name) === normalizeName(kind, name))).toBe(true);
    }
    // The generator must exercise both outcomes, or the test proves nothing.
    expect(edits).toBeGreaterThan(300);
    expect(refusals).toBeGreaterThan(300);
  });

  test("giant inputs finish quickly", () => {
    const started = performance.now();
    const many = `{"dependencies":{${Array.from({ length: 15_000 }, (_, i) => `"p${i}":"1.0.0"`).join(",")}}}`;
    expect(many.length).toBeLessThan(MAX_MANIFEST_BYTES);
    expect(ok(edit("npm", many, "p14999", "1.0.1")).changes).toHaveLength(1);
    const longLine = `a==1.0.0 ${"#".repeat(500_000)}\n`;
    expect(() => edit("pypi", longLine, "a", "1.0.1")).not.toThrow();
    const lines = "x==1.0\n".repeat(100_000).slice(0, MAX_MANIFEST_BYTES);
    expect(refused(edit("pypi", lines, "x", "2.0"))).toBe("invalid"); // more than 20,000 entries
    expect(performance.now() - started).toBeLessThan(5000);
  });

  test("odd encodings: replacement characters and lone surrogates do not break the scanner", () => {
    const text = '{"description":"caf� \uD800 broken","dependencies":{"a":"1.0.0"}}';
    expect(ok(edit("npm", text, "a", "1.0.1")).text).toContain('"a":"1.0.1"');
    expect(ok(edit("pypi", "a==1.0\n# caf�\n", "a", "1.1")).text).toBe("a==1.1\n# caf�\n");
  });
});
