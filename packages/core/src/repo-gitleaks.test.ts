import { describe, expect, it } from "vitest";
import { cleanRepoGitleaksConfig, mergeRepoRun, REPO_GITLEAKS_MAX_BYTES } from "./repo-gitleaks.ts";
import type { SecretHit } from "./secrets.ts";

const config = (text: string) => {
  const out = cleanRepoGitleaksConfig(text);
  if (!("config" in out)) throw new Error(out.problem);
  return out.config;
};

describe("the repository's gitleaks configuration", () => {
  it("replaces [extend] so that it cannot pull in another file, keeping disabledRules", () => {
    const out = config(`title = "repo"
[extend]
path = "/etc/passwd"
useDefault = false
disabledRules = [
  "generic-api-key", # noisy
  "jwt",
]

[[rules]]
id = "acme-key"
regex = '''acme_[a-z]{24}'''

[allowlist]
paths = ['''test/fixtures/.*''']
`);
    expect(out).not.toContain("/etc/passwd");
    expect(out).not.toContain("useDefault = false");
    expect(out).toContain('id = "acme-key"');
    expect(out).toContain("[allowlist]");
    expect(out).toMatch(/\[extend\]\nuseDefault = true\ndisabledRules = \[ "generic-api-key",/);
    expect(out.match(/\[extend\]/g)).toHaveLength(1);
  });

  it("adds useDefault when there is no [extend]", () => {
    expect(config('[[rules]]\nid = "x-key"\nregex = "x"\n')).toMatch(/\[extend\]\nuseDefault = true\n$/);
  });

  it("refuses files it cannot use safely", () => {
    expect(cleanRepoGitleaksConfig('extend = { path = "/etc/passwd" }')).toEqual({ problem: "extendForm" });
    expect(cleanRepoGitleaksConfig('extend.path = "/etc/passwd"')).toEqual({ problem: "extendForm" });
    expect(cleanRepoGitleaksConfig('[[rules]]\nid = "garnetops-env-file"\n')).toEqual({
      problem: "reservedRuleId",
    });
    expect(cleanRepoGitleaksConfig("a\u0000b")).toEqual({ problem: "notText" });
    expect(cleanRepoGitleaksConfig("#".repeat(REPO_GITLEAKS_MAX_BYTES + 1))).toEqual({ problem: "tooLarge" });
  });
});

describe("the two runs compared", () => {
  const hit = (over: Partial<SecretHit>): SecretHit => ({
    ruleId: "github-pat",
    severity: "critical",
    path: "src/a.js",
    line: 1,
    commit: null,
    committedAt: null,
    fingerprint: "fp-a",
    ...over,
  });

  it("sets aside what only the strict run has, and adds what only the repository's rules found", () => {
    const strict = [
      hit({}),
      hit({ fingerprint: "fp-b", path: "src/b.js" }),
      hit({ ruleId: "generic-api-key", fingerprint: "fp-c", path: "src/c.txt" }),
    ];
    const repo = [
      hit({}),
      // The same value at the same place under the repository's own rule: the same place, not a new one.
      hit({ ruleId: "acme-key", fingerprint: "fp-c", path: "src/c.txt" }),
      hit({ ruleId: "acme-key", fingerprint: "fp-d", path: "src/d.txt" }),
      hit({ ruleId: "acme-key-2", fingerprint: "fp-d", path: "src/d.txt" }),
    ];
    const merged = mergeRepoRun(strict, repo);
    expect(merged.added).toBe(1);
    expect(merged.hits.map((h) => [h.ruleId, h.path])).toEqual([
      ["github-pat", "src/a.js"],
      ["github-pat", "src/b.js"],
      ["generic-api-key", "src/c.txt"],
      ["acme-key", "src/d.txt"],
    ]);
    expect([...merged.setAside]).toEqual(["fp-b\u0000src/b.js\u00001\u0000"]);
  });
});
