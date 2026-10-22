import { describe, expect, test } from "vitest";
import {
  advisoryUrl,
  apiBaseProblem,
  branchName,
  buildProposals,
  defaultApiBase,
  detectForge,
  escapeMarkdown,
  type FindingFact,
  type FixPrInput,
  inlineCode,
  isProposalKey,
  type ManifestFact,
  parseRepoLocation,
  proposalKey,
  pullRequestUrl,
  renderPullRequest,
  renovateConfig,
} from "./fix-prs.ts";
import { listDependencies } from "./manifests.ts";

describe("repository location", () => {
  test("https and SSH forms", () => {
    expect(parseRepoLocation("https://git.example.com/team/app.git")).toEqual({
      host: "git.example.com",
      owner: "team",
      repo: "app",
      webBase: "https://git.example.com/team/app",
    });
    expect(parseRepoLocation("git@git.example.com:team/app.git")?.webBase).toBe(
      "https://git.example.com/team/app",
    );
    expect(parseRepoLocation("ssh://git@git.example.com:2222/team/app")?.webBase).toBe(
      "https://git.example.com/team/app",
    );
    expect(parseRepoLocation("https://GitHub.com/Org/Repo")?.host).toBe("github.com");
  });
  test("a forge under a path prefix keeps it, a port stays", () => {
    expect(parseRepoLocation("https://example.com:8443/git/team/app.git")?.webBase).toBe(
      "https://example.com:8443/git/team/app",
    );
  });
  test("rejects what is not owner/repo", () => {
    for (const bad of [
      "https://example.com/app",
      "https://user:pw@example.com/a/b",
      "https://example.com/a/b?x=1",
      "git@example.com:a/b/c",
      "https://example.com/a/b c",
      "https://example.com/a/..",
      "not a url",
    ]) {
      expect(parseRepoLocation(bad), bad).toBeNull();
    }
  });
  test("forge detection and API addresses", () => {
    expect(detectForge("github.com")).toBe("github");
    expect(detectForge("codeberg.org")).toBe("forgejo");
    expect(detectForge("forgejo.example.com")).toBe("forgejo");
    expect(detectForge("git.gitea.example.lan:3000")).toBe("gitea");
    expect(detectForge("git.example.com")).toBeNull();
    expect(defaultApiBase("github", "github.com")).toBe("https://api.github.com");
    expect(defaultApiBase("github", "ghe.example.com")).toBe("https://ghe.example.com/api/v3");
    expect(defaultApiBase("gitea", "git.example.com")).toBe("https://git.example.com/api/v1");
    expect(defaultApiBase("forgejo", "git.example.com:3000")).toBe("https://git.example.com:3000/api/v1");
    expect(pullRequestUrl("github", "https://github.com/o/r", 7)).toBe("https://github.com/o/r/pull/7");
    expect(pullRequestUrl("forgejo", "https://git.example.com/o/r", 7)).toBe(
      "https://git.example.com/o/r/pulls/7",
    );
  });
  test("an API address must be https and look like the forge's API", () => {
    expect(apiBaseProblem("github", "https://api.github.com")).toBeNull();
    expect(apiBaseProblem("github", "https://ghe.example.com/api/v3")).toBeNull();
    expect(apiBaseProblem("gitea", "https://git.example.com/sub/api/v1/")).toBeNull();
    for (const [kind, value] of [
      ["github", "http://api.github.com"],
      ["github", "https://ghe.example.com/"],
      ["gitea", "https://git.example.com/api/v3"],
      ["gitea", "https://user:pw@git.example.com/api/v1"],
      ["gitea", "https://git.example.com/api/v1?x=1"],
      ["gitea", "https://localhost/api/v1"],
      ["gitea", "https://169.254.169.254/api/v1"],
      ["gitea", "https://127.0.0.1/api/v1"],
      ["gitea", "https://[::1]/api/v1"],
      ["gitea", "ftp://git.example.com/api/v1"],
      ["gitea", "nope"],
    ] as const) {
      expect(apiBaseProblem(kind, value), value).not.toBeNull();
    }
    // A private address is fine: a self-hosted forge is the normal case.
    expect(apiBaseProblem("gitea", "https://192.168.1.20/api/v1")).toBeNull();
  });
});

const finding = (patch: Partial<FindingFact> & { id: string }): FindingFact => ({
  vulnerabilityId: `CVE-2099-${patch.id}`,
  severity: "high",
  severityRank: 4,
  packageName: "lodash",
  packageType: "npm",
  packageVersion: "4.17.20",
  fixedIn: ["4.17.21"],
  locations: ["/package-lock.json"],
  ...patch,
});

function manifest(path: string, kind: ManifestFact["kind"], text: string): ManifestFact {
  return { path, kind, blobSha: "a".repeat(40), dependencies: listDependencies(kind, text) ?? [] };
}

const pkgJson = manifest(
  "package.json",
  "npm",
  JSON.stringify({
    dependencies: { lodash: "^4.17.20", express: "4.18.1", range: ">=1 <3", fine: "^5.0.0" },
    devDependencies: { mocha: "^9.0.0" },
  }),
);

describe("buildProposals", () => {
  test("one proposal per package and manifest, with the vulnerabilities it fixes", () => {
    const [p, ...rest] = buildProposals({
      repositoryId: "repo_1",
      findings: [
        finding({ id: "a", severity: "medium", severityRank: 3, fixedIn: ["4.17.21", "3.9.0"] }),
        finding({ id: "b", severity: "critical", severityRank: 5, fixedIn: ["4.17.21"] }),
      ],
      manifests: [pkgJson],
    });
    expect(rest).toHaveLength(0);
    expect(p).toMatchObject({
      packageName: "lodash",
      ecosystem: "npm",
      installedVersion: "4.17.20",
      targetVersion: "4.17.21",
      majorUpgrade: false,
      severity: "critical",
      vulnerabilityIds: ["CVE-2099-a", "CVE-2099-b"],
      manifestPath: "package.json",
      dependency: "direct",
      section: "dependencies",
      currentSpec: "^4.17.20",
      newSpec: "^4.17.21",
      action: "edit",
      reason: null,
    });
    expect(isProposalKey(p?.key ?? "")).toBe(true);
  });

  test("a major upgrade is marked", () => {
    const [p] = buildProposals({
      repositoryId: "repo_1",
      findings: [finding({ id: "a", packageName: "express", packageVersion: "4.18.1", fixedIn: ["5.0.1"] })],
      manifests: [pkgJson],
    });
    expect(p).toMatchObject({ targetVersion: "5.0.1", majorUpgrade: true, action: "edit", newSpec: "5.0.1" });
  });

  test("a package the manifest does not declare is transitive and gets no edit", () => {
    const [p] = buildProposals({
      repositoryId: "repo_1",
      findings: [finding({ id: "a", packageName: "minimist", packageVersion: "1.2.0", fixedIn: ["1.2.6"] })],
      manifests: [pkgJson],
    });
    expect(p).toMatchObject({
      dependency: "transitive",
      action: "manual",
      reason: "transitive",
      targetVersion: "1.2.6",
    });
  });

  test("a complex range, an already satisfied range, no manifest, no fix and an unsupported ecosystem say why", () => {
    const run = (f: Partial<FindingFact>, manifests: ManifestFact[] = [pkgJson]) =>
      buildProposals({
        repositoryId: "repo_1",
        findings: [finding({ id: "a", ...f })],
        manifests,
      })[0];
    expect(run({ packageName: "range", packageVersion: "1.5.0", fixedIn: ["2.0.0"] })).toMatchObject({
      action: "manual",
      reason: "complex-range",
    });
    expect(run({ packageName: "fine", packageVersion: "5.0.0", fixedIn: ["5.0.1"] })).toMatchObject({
      action: "edit",
    });
    expect(run({ packageName: "fine", packageVersion: "4.0.0", fixedIn: ["4.9.9"] })).toMatchObject({
      action: "manual",
      reason: "already-satisfied",
    });
    expect(run({}, [])).toMatchObject({ action: "manual", reason: "no-manifest" });
    expect(run({ locations: ["/node_modules/lodash/package.json"] })).toMatchObject({
      reason: "no-manifest",
    });
    expect(run({ fixedIn: ["nonsense"] })).toMatchObject({
      action: "manual",
      reason: "no-version",
      targetVersion: null,
    });
    expect(run({ packageType: "java-archive", locations: ["/pom.xml"], packageName: "x" })).toMatchObject({
      action: "manual",
      reason: "unsupported-ecosystem",
    });
  });

  test("findings without a fixed version make no proposal", () => {
    expect(
      buildProposals({
        repositoryId: "repo_1",
        findings: [finding({ id: "a", fixedIn: [] })],
        manifests: [pkgJson],
      }),
    ).toEqual([]);
  });

  test("the same package in two manifests makes two proposals", () => {
    const other = manifest(
      "web/package.json",
      "npm",
      JSON.stringify({ dependencies: { lodash: "~4.17.0" } }),
    );
    const proposals = buildProposals({
      repositoryId: "repo_1",
      findings: [finding({ id: "a", locations: ["/package-lock.json", "/web/package-lock.json"] })],
      manifests: [pkgJson, other],
    });
    expect(proposals.map((p) => [p.manifestPath, p.newSpec]).sort()).toEqual([
      ["package.json", "^4.17.21"],
      ["web/package.json", "~4.17.21"],
    ]);
    expect(new Set(proposals.map((p) => p.key)).size).toBe(2);
  });

  test("sorted worst first", () => {
    const proposals = buildProposals({
      repositoryId: "repo_1",
      findings: [
        finding({
          id: "a",
          packageName: "express",
          packageVersion: "4.18.1",
          severity: "low",
          severityRank: 2,
        }),
        finding({ id: "b", severity: "critical", severityRank: 5 }),
      ],
      manifests: [pkgJson],
    });
    expect(proposals.map((p) => p.packageName)).toEqual(["lodash", "express"]);
  });

  test("Python, Go, Cargo and Composer", () => {
    const manifests = [
      manifest("requirements.txt", "pypi", "requests==2.25.0\n"),
      manifest(
        "go.mod",
        "go",
        "module m\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/text v0.3.7 // indirect\n)\n",
      ),
      manifest("Cargo.toml", "cargo", '[dependencies]\nserde = "1.0.150"\n'),
      manifest("composer.json", "composer", '{"require":{"monolog/monolog":"^2.8"}}'),
    ];
    const proposals = buildProposals({
      repositoryId: "repo_1",
      manifests,
      findings: [
        finding({
          id: "p",
          packageType: "python",
          packageName: "requests",
          packageVersion: "2.25.0",
          fixedIn: ["2.31.0"],
          locations: ["/requirements.txt"],
        }),
        finding({
          id: "g",
          packageType: "go-module",
          packageName: "github.com/gin-gonic/gin",
          packageVersion: "v1.9.0",
          fixedIn: ["1.9.1"],
          locations: ["/go.mod"],
        }),
        finding({
          id: "t",
          packageType: "go-module",
          packageName: "golang.org/x/text",
          packageVersion: "v0.3.7",
          fixedIn: ["0.3.8"],
          locations: ["/go.mod"],
        }),
        finding({
          id: "c",
          packageType: "rust-crate",
          packageName: "serde",
          packageVersion: "1.0.150",
          fixedIn: ["1.0.190"],
          locations: ["/Cargo.lock"],
        }),
        finding({
          id: "m",
          packageType: "php-composer",
          packageName: "monolog/monolog",
          packageVersion: "2.8.0",
          fixedIn: ["2.9.1"],
          locations: ["/composer.lock"],
        }),
      ],
    });
    const by = (name: string) => proposals.find((p) => p.packageName === name);
    expect(by("requests")).toMatchObject({ ecosystem: "pypi", newSpec: "==2.31.0", action: "edit" });
    expect(by("github.com/gin-gonic/gin")).toMatchObject({
      ecosystem: "go",
      targetVersion: "1.9.1",
      newSpec: "v1.9.1",
      action: "edit",
    });
    expect(by("golang.org/x/text")).toMatchObject({
      dependency: "transitive",
      action: "manual",
      reason: "transitive",
    });
    expect(by("serde")).toMatchObject({ ecosystem: "cargo", newSpec: "1.0.190", action: "edit" });
    expect(by("monolog/monolog")).toMatchObject({ ecosystem: "composer", newSpec: "^2.9.1", action: "edit" });
  });

  test("a declaration that can never be edited is reported with its reason", () => {
    const m = manifest(
      "package.json",
      "npm",
      '{"dependencies":{"a":"git+https://example.com/a.git","b":"1.0.0","b":"1.0.1"}}',
    );
    const run = (name: string) =>
      buildProposals({
        repositoryId: "repo_1",
        findings: [finding({ id: "a", packageName: name, packageVersion: "1.0.0", fixedIn: ["1.5.0"] })],
        manifests: [m],
      })[0];
    expect(run("a")).toMatchObject({ action: "manual", reason: "unsupported-source" });
    expect(run("b")).toMatchObject({ action: "manual", reason: "ambiguous" });
  });

  test("the key follows the change", () => {
    const base = {
      repositoryId: "r",
      packageType: "npm",
      manifestPath: "package.json",
      packageName: "a",
      targetVersion: "1.0.1",
    };
    expect(proposalKey(base)).toBe(proposalKey({ ...base }));
    expect(proposalKey(base)).not.toBe(proposalKey({ ...base, targetVersion: "1.0.2" }));
    expect(proposalKey(base)).not.toBe(proposalKey({ ...base, manifestPath: "web/package.json" }));
    expect(proposalKey(base)).not.toBe(proposalKey({ ...base, repositoryId: "r2" }));
  });
});

describe("branch names", () => {
  test("garnetops/fix-<package>-<version>", () => {
    expect(branchName("lodash", "4.17.21")).toBe("garnetops/fix-lodash-4.17.21");
    expect(branchName("@scope/pkg", "1.0.0")).toBe("garnetops/fix-scope-pkg-1.0.0");
    expect(branchName("github.com/gin-gonic/gin", "1.9.1")).toBe(
      "garnetops/fix-github.com-gin-gonic-gin-1.9.1",
    );
  });
  test("hostile names stay valid ref names", () => {
    for (const [name, version] of [
      ["a b;rm -rf /", "1.0.0"],
      ["..", "..."],
      ["x".repeat(500), "1.0.0"],
      ["a.lock", "1"],
      ["$(whoami)", "`id`"],
      ["a\nb", "1\r\n2"],
      ["", ""],
      ["é€", "1"],
    ] as const) {
      const branch = branchName(name, version);
      expect(branch, branch).toMatch(/^garnetops\/fix-[A-Za-z0-9][A-Za-z0-9._-]*$/);
      expect(branch.length).toBeLessThanOrEqual(100);
      expect(branch).not.toContain("..");
      expect(branch.endsWith(".lock")).toBe(false);
      expect(branch.endsWith(".")).toBe(false);
    }
    expect(branchName("x".repeat(500), "1.0.0")).not.toBe(branchName("x".repeat(501), "1.0.0"));
  });
});

/** Markdown with its code spans cut out, by the CommonMark rule: a run of n backticks closes at the next run of exactly n. */
function withoutCodeSpans(text: string): string {
  let out = "";
  let i = 0;
  while (i < text.length) {
    if (text[i] !== "`") {
      out += text[i];
      i++;
      continue;
    }
    let n = 0;
    while (text[i + n] === "`") n++;
    let j = i + n;
    let close = -1;
    while (j < text.length) {
      if (text[j] !== "`") {
        j++;
        continue;
      }
      let m = 0;
      while (text[j + m] === "`") m++;
      if (m === n) {
        close = j;
        break;
      }
      j += m;
    }
    if (close < 0) {
      out += text.slice(i, i + n);
      i += n;
    } else {
      out += "\u0000";
      i = close + n;
    }
  }
  return out;
}

describe("pull request text", () => {
  const input: FixPrInput = {
    packageName: "lodash",
    ecosystem: "npm",
    fromVersion: "4.17.20",
    toVersion: "4.17.21",
    majorUpgrade: false,
    manifestPath: "package.json",
    vulnerabilities: [
      { id: "CVE-2099-0001", severity: "critical", url: advisoryUrl("CVE-2099-0001") },
      { id: "GHSA-aaaa-bbbb-cccc", severity: "high", url: null },
    ],
    requestedBy: "Erika Example",
  };

  test("the fixed template", () => {
    const { title, body, commitMessage } = renderPullRequest(input);
    expect(title).toBe("fix(deps): update lodash from 4.17.20 to 4.17.21");
    expect(commitMessage).toBe("fix(deps): update lodash to 4.17.21");
    expect(body).toContain("`lodash`: `4.17.20` → `4.17.21` in `package.json`");
    expect(body).toContain("[`CVE-2099-0001`](https://nvd.nist.gov/vuln/detail/CVE-2099-0001) (critical)");
    expect(body).toContain("- `GHSA-aaaa-bbbb-cccc` (high)");
    expect(body).toContain("The lockfile is **not** updated");
    expect(body).toContain("package-lock.json, yarn.lock or pnpm-lock.yaml");
    expect(body).toContain("Created by GarnetOps at the request of `Erika Example`. Review before merging.");
    expect(body).not.toContain("Major upgrade");
  });

  test("a major upgrade says so", () => {
    expect(renderPullRequest({ ...input, majorUpgrade: true }).body).toContain("**Major upgrade.**");
  });

  test("hostile text cannot break out of its code span or inject Markdown, mentions or links", () => {
    const evil =
      "`]( javascript:alert(1)) @everyone <script>alert(1)</script>\n# heading ![x](https://evil.example/x.png)";
    const { body, title } = renderPullRequest({
      ...input,
      packageName: evil,
      fromVersion: evil,
      toVersion: evil,
      manifestPath: evil,
      requestedBy: evil,
      vulnerabilities: [
        { id: "CVE-2099-0001\n# x", severity: evil, url: "https://evil.example/)[x](javascript:1" },
        { id: "ok-1", severity: evil, url: null },
      ],
    });
    expect(title).not.toContain("\n");
    // The dangerous text only ever appears inside a code span: outside them, only template text is left.
    const outside = withoutCodeSpans(body);
    for (const line of body.split("\n")) expect(line).not.toMatch(/^#+ heading/);
    expect(outside).not.toContain("@everyone");
    expect(outside).not.toContain("<script>");
    expect(outside).not.toContain("javascript:alert(1))");
    expect(outside.split("\n").filter((l) => l.startsWith("#"))).toEqual([
      "## Dependency update",
      "### Vulnerabilities fixed",
      "### Before you merge",
    ]);
    // The identifier with a newline is dropped, the other is listed; a severity that is not one of ours becomes "unknown".
    expect(body).toContain("`ok-1` (unknown)");
    expect(body).not.toContain("CVE-2099-0001\n");
    expect(body).toContain("`ok-1`");
    expect(body).not.toMatch(/\(https:\/\/evil\.example\/\)\[x\]/);
  });

  test("backticks in values cannot close the code span", () => {
    expect(inlineCode("a`b")).toBe("``a`b``");
    expect(inlineCode("`a`")).toBe("`` `a` ``");
    expect(inlineCode("a``b`c")).toBe("```a``b`c```");
    expect(inlineCode("line\none")).toBe("`line one`");
  });

  test("escapeMarkdown", () => {
    expect(escapeMarkdown("*bold* [x](y) <b> #1 @a | `c` ~~s~~ a_b")).toBe(
      "\\*bold\\* \\[x\\]\\(y\\) \\<b\\> \\#1 \\@a \\| \\`c\\` \\~\\~s\\~\\~ a\\_b",
    );
    expect(escapeMarkdown("a‮b\u0000c\nd")).toBe("a b c d");
  });

  test("long lists are cut", () => {
    const many = Array.from({ length: 60 }, (_, i) => ({
      id: `CVE-2099-${String(i).padStart(4, "0")}`,
      severity: "low",
      url: null,
    }));
    const { body } = renderPullRequest({ ...input, vulnerabilities: many });
    expect(body).toContain("- and 35 more");
    expect(body.length).toBeLessThan(6000);
  });

  test("advisory links", () => {
    expect(advisoryUrl("CVE-2099-0001")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2099-0001");
    expect(advisoryUrl("GHSA-aaaa-bbbb-cccc")).toBeNull();
    expect(advisoryUrl("GHSA-2ccf-ffrj-m4qw")).toBe("https://github.com/advisories/GHSA-2ccf-ffrj-m4qw");
    expect(
      advisoryUrl("PYSEC-1", [
        "http://x.example/a",
        "javascript:alert(1)",
        "https://user:pw@x.example/a",
        "https://x.example/a(b)",
      ]),
    ).toBe("https://x.example/a%28b%29");
    expect(advisoryUrl("bad id")).toBeNull();
  });
});

describe("Renovate configuration", () => {
  test("a rule per package at the highest proposed version, alerts on", () => {
    const config = renovateConfig([
      { packageName: "lodash", ecosystem: "npm", targetVersion: "4.17.21" },
      { packageName: "lodash", ecosystem: "npm", targetVersion: "4.17.30" },
      { packageName: "requests", ecosystem: "pypi", targetVersion: "2.31.0" },
      { packageName: "weird;name", ecosystem: "npm", targetVersion: "1.0.0" },
      { packageName: "x", ecosystem: null, targetVersion: "1.0.0" },
      { packageName: "y", ecosystem: "go", targetVersion: null },
    ]) as { vulnerabilityAlerts: { enabled: boolean }; packageRules: Record<string, unknown>[] };
    expect(config.vulnerabilityAlerts.enabled).toBe(true);
    expect(config.packageRules.map((r) => [r.matchManagers, r.matchPackageNames, r.allowedVersions])).toEqual(
      [
        [["npm"], ["lodash"], ">=4.17.30"],
        [["pip_requirements"], ["requests"], ">=2.31.0"],
      ],
    );
  });
});
