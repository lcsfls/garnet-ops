import { describe, expect, it } from "vitest";
import { redactGitleaksReport, secretFingerprint } from "./secret-fingerprint.ts";
import {
  cleanSecretPath,
  gitleaksArgs,
  gitleaksConfig,
  ignorePatternProblem,
  ignorePatternRegExp,
  ignoringRule,
  isSensitiveFileRule,
  matchingIgnoreRule,
  parseGitleaksReport,
  SENSITIVE_FILE_RULES,
  secretSeverity,
} from "./secrets.ts";

// Built at run time: a literal token-shaped value in a test file would trip our own secret scanning.
const token = `ghp_${"x7Kq".repeat(9)}`;
const key = new Uint8Array(32).fill(7);
const fp = (ruleId: string, secret: string, path: string) => secretFingerprint(key, ruleId, secret, path);

const entry = (over: Record<string, unknown> = {}) => ({
  RuleID: "github-pat",
  Description: "GitHub Personal Access Token",
  File: "/work/scan-1/src/app/config.js",
  StartLine: 12,
  EndLine: 12,
  Secret: token,
  Match: `const token = "${token}"`,
  Commit: "",
  Date: "",
  Author: "Someone",
  Email: "someone@example.com",
  Message: "",
  Fingerprint: `app/config.js:github-pat:12`,
  ...over,
});

describe("severities", () => {
  it("are fixed per rule: infrastructure and supply chain critical, guesses medium, public ids low", () => {
    expect(secretSeverity("private-key")).toBe("critical");
    expect(secretSeverity("aws-access-token")).toBe("critical");
    expect(secretSeverity("github-fine-grained-pat")).toBe("critical");
    expect(secretSeverity("npm-access-token")).toBe("critical");
    expect(secretSeverity("slack-bot-token")).toBe("high");
    expect(secretSeverity("openai-api-key")).toBe("high");
    expect(secretSeverity("some-rule-from-a-newer-gitleaks")).toBe("high");
    expect(secretSeverity("generic-api-key")).toBe("medium");
    expect(secretSeverity("jwt")).toBe("medium");
    expect(secretSeverity("discord-client-id")).toBe("low");
    expect(secretSeverity("mailgun-pub-key")).toBe("low");
    expect(secretSeverity("garnetops-ssh-private-key-file")).toBe("critical");
    expect(secretSeverity("garnetops-database-dump")).toBe("medium");
    // "github-" must not make a rule critical that only starts with the letters.
    expect(secretSeverity("githubx-token")).toBe("high");
  });

  it("knows which rules are about whole files", () => {
    expect(isSensitiveFileRule("garnetops-env-file")).toBe(true);
    expect(isSensitiveFileRule("github-pat")).toBe(false);
  });
});

describe("the gitleaks configuration", () => {
  const config = gitleaksConfig();

  it("extends gitleaks' default rules with every file rule of ours", () => {
    expect(config).toContain("[extend]\nuseDefault = true");
    for (const rule of SENSITIVE_FILE_RULES) {
      expect(config).toContain(`id = "${rule.id}"`);
      expect(rule.id).toMatch(/^garnetops-[a-z0-9-]+$/);
    }
    expect(config.match(/\[\[rules\]\]/g)).toHaveLength(SENSITIVE_FILE_RULES.length);
    // Examples are allowed only where the rule says so, as an allowlist of that rule.
    expect(config).toContain("[[rules.allowlists]]");
  });

  it("always names our configuration and never the repository's suppressions", () => {
    const args = gitleaksArgs({
      configPath: "/cfg.toml",
      emptyDir: "/empty",
      reportPath: "/out/report.json",
    });
    expect(args).toEqual(expect.arrayContaining(["--config", "/cfg.toml", "--ignore-gitleaks-allow"]));
    expect(args[args.indexOf("--gitleaks-ignore-path") + 1]).toBe("/empty");
    expect(args).not.toContain("--verbose");
    // No redaction flag needed: the report never leaves the worker's memory, and the value is dropped while reading it.
    expect(args[args.indexOf("--exit-code") + 1]).toBe("0");
  });

  it("matches the files it is meant for (RE2 patterns, checked here with the same syntax)", () => {
    const path = (id: string) => {
      const rule = SENSITIVE_FILE_RULES.find((r) => r.id === id);
      return new RegExp((rule?.path ?? "").replace(/^\(\?i\)/, ""), rule?.path.startsWith("(?i)") ? "i" : "");
    };
    expect(path("garnetops-env-file").test("deploy/.env")).toBe(true);
    expect(path("garnetops-env-file").test(".env.production")).toBe(true);
    expect(path("garnetops-env-file").test("src/environment.ts")).toBe(false);
    expect(path("garnetops-ssh-private-key-file").test("keys/id_ed25519")).toBe(true);
    expect(path("garnetops-ssh-private-key-file").test("keys/id_ed25519.pub")).toBe(false);
    expect(path("garnetops-ai-agent-local-settings").test("a/.claude/settings.local.json")).toBe(true);
    expect(path("garnetops-ai-agent-local-settings").test(".claude/settings.json")).toBe(false);
    expect(path("garnetops-database-dump").test("db/migrations/0001.sql")).toBe(false);
    expect(path("garnetops-terraform-state").test("infra/terraform.tfstate.backup")).toBe(true);
  });
});

describe("reading gitleaks' report", () => {
  it("keeps rule, path, line and fingerprint, and nothing of the value, the match or the author", () => {
    const parsed = parseGitleaksReport(JSON.stringify([entry()]), {
      root: "/work/scan-1/src",
      fingerprint: fp,
    });
    expect(parsed).toMatchObject({ dropped: 0, invalid: 0 });
    expect(parsed.hits).toEqual([
      {
        ruleId: "github-pat",
        severity: "critical",
        path: "app/config.js",
        line: 12,
        commit: null,
        committedAt: null,
        fingerprint: fp("github-pat", token, "app/config.js"),
      },
    ]);
    const stored = JSON.stringify(parsed);
    expect(stored).not.toContain(token);
    expect(stored).not.toContain("x7Kq");
    expect(stored).not.toContain("someone");
  });

  it("gives the same secret the same fingerprint in every file, and a file rule one per path", () => {
    const parsed = parseGitleaksReport(
      JSON.stringify([
        entry(),
        entry({ File: "/work/scan-1/src/other.js", StartLine: 3 }),
        entry({ RuleID: "garnetops-env-file", File: "/work/scan-1/src/.env", StartLine: 0, Secret: "" }),
        entry({ RuleID: "garnetops-env-file", File: "/work/scan-1/src/api/.env", StartLine: 0, Secret: "" }),
      ]),
      { root: "/work/scan-1/src", fingerprint: fp },
    );
    const [a, b, c, d] = parsed.hits;
    expect(a?.fingerprint).toBe(b?.fingerprint);
    expect(c?.line).toBeNull();
    expect(c?.fingerprint).not.toBe(d?.fingerprint);
    expect(c?.severity).toBe("high");
  });

  it("takes commit and date from a history scan, and drops a file rule's value even if one is sent", () => {
    const commit = "a".repeat(40);
    const parsed = parseGitleaksReport(
      JSON.stringify([
        entry({ File: "config/old.ini", Commit: commit, Date: "2026-01-02T03:04:05Z" }),
        entry({ RuleID: "garnetops-env-file", File: ".env", StartLine: 0, Secret: "should-not-matter" }),
      ]),
      { root: "/clone", fingerprint: fp },
    );
    expect(parsed.hits[0]).toMatchObject({
      path: "config/old.ini",
      commit,
      committedAt: "2026-01-02T03:04:05.000Z",
    });
    expect(parsed.hits[1]?.fingerprint).toBe(fp("garnetops-env-file", "", ".env"));
  });

  it("refuses paths outside the repository and odd entries, counts what it drops, and reads an empty report", () => {
    const parsed = parseGitleaksReport(
      JSON.stringify([
        entry({ File: "../../etc/passwd" }),
        entry({ File: "/etc/passwd" }),
        entry({ RuleID: "Bad Rule!" }),
        entry({ File: "" }),
        null,
        "text",
        entry(),
        entry(),
        entry({ StartLine: 13 }),
        entry({ StartLine: 14 }),
      ]),
      { root: "/work/scan-1/src", fingerprint: fp, maxHits: 2 },
    );
    expect(parsed.hits.map((h) => h.line)).toEqual([12, 13]);
    expect(parsed.dropped).toBe(1);
    expect(parsed.invalid).toBe(6);
    expect(parseGitleaksReport("", { root: "/", fingerprint: fp }).hits).toEqual([]);
    expect(() => parseGitleaksReport("{}", { root: "/", fingerprint: fp })).toThrow("not a list");
  });

  it("cleans paths: separators, control and bidirectional characters, the scan root", () => {
    expect(cleanSecretPath("C:\\scan\\src\\a\\b.txt", "C:\\scan\\src")).toBe("a/b.txt");
    expect(cleanSecretPath("./a/\u202eb.txt", "/x")).toBe("a/b.txt");
    expect(cleanSecretPath("a//b", "/x")).toBeNull();
    expect(cleanSecretPath("a/../b", "/x")).toBeNull();
    expect(cleanSecretPath("a".repeat(501), "/x")).toBeNull();
  });
});

describe("the fingerprint", () => {
  it("depends on the key, so it cannot be checked against a guess without it", () => {
    const other = new Uint8Array(32).fill(8);
    expect(secretFingerprint(key, "github-pat", token, "a")).toBe(
      secretFingerprint(key, "aws-access-token", token, "b"),
    );
    expect(secretFingerprint(key, "github-pat", token, "a")).not.toBe(
      secretFingerprint(other, "github-pat", token, "a"),
    );
    expect(secretFingerprint(key, "github-pat", token, "a")).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(() => secretFingerprint(new Uint8Array(16), "r", "s", "p")).toThrow("too short");
  });
});

describe("the report as it leaves the scanner", () => {
  it("holds no value, matched text, author or message: only the value's SHA-256", () => {
    const redacted = redactGitleaksReport(
      JSON.stringify([
        entry(),
        entry({ RuleID: "garnetops-env-file", File: ".env", StartLine: 0, Secret: "x" }),
      ]),
    );
    expect(redacted).not.toContain(token);
    expect(redacted).not.toContain("x7Kq");
    expect(redacted).not.toMatch(/someone|Someone|Match|Author|Email|Message|Fingerprint/);
    const [value, file] = JSON.parse(redacted) as { Secret: string }[];
    expect(value?.Secret).toMatch(/^[0-9a-f]{64}$/);
    expect(file?.Secret).toBe("");
    // The worker reads it as before; the same value gives the same fingerprint in every file.
    const parsed = parseGitleaksReport(redacted, { root: "/work/scan-1/src", fingerprint: fp });
    expect(parsed.hits[0]?.fingerprint).toBe(fp("github-pat", value?.Secret ?? "", "app/config.js"));
    expect(redactGitleaksReport("")).toBe("[]");
    expect(() => redactGitleaksReport('{"a":1}')).toThrow("not a list");
  });
});

describe("ignore rules", () => {
  it("match globs over the whole path", () => {
    const m = (pattern: string, path: string) => ignorePatternRegExp(pattern).test(path);
    expect(m("test/fixtures/**", "test/fixtures/a/b.json")).toBe(true);
    expect(m("test/fixtures/**", "src/test/fixtures/a.json")).toBe(false);
    expect(m("**/fixtures/**", "src/test/fixtures/a.json")).toBe(true);
    expect(m("**/*.example.env", "deploy/prod.example.env")).toBe(true);
    expect(m("**/*.example.env", "prod.example.env")).toBe(true);
    expect(m("docs/*.md", "docs/a.md")).toBe(true);
    expect(m("docs/*.md", "docs/sub/a.md")).toBe(false);
    expect(m("a?.txt", "ab.txt")).toBe(true);
    // Dots and other characters are literal.
    expect(m("a.txt", "abtxt")).toBe(false);
    expect(m("(x)+", "(x)+")).toBe(true);
  });

  it("refuse patterns that are absolute, climb out, are too wide or carry odd characters", () => {
    expect(ignorePatternProblem("test/**")).toBeNull();
    expect(ignorePatternProblem("/etc/**")).toBe("not-relative");
    expect(ignorePatternProblem("a/../b")).toBe("not-relative");
    expect(ignorePatternProblem("**")).toBe("everything");
    expect(ignorePatternProblem("*/**/*")).toBe("everything");
    expect(ignorePatternProblem("a[bc]")).toBe("characters");
    expect(ignorePatternProblem("x".repeat(201))).toBe("too-long");
    expect(ignorePatternProblem("  ")).toBe("empty");
  });

  it("apply by repository, rule and path, and set a finding aside only when every place is covered", () => {
    const rules = [
      { id: "r1", repositoryId: "repo_a", pathPattern: "test/**", ruleId: null },
      { id: "r2", repositoryId: null, pathPattern: null, ruleId: "jwt" },
    ];
    expect(
      matchingIgnoreRule(rules, { repositoryId: "repo_a", ruleId: "github-pat", path: "test/x.js" })?.id,
    ).toBe("r1");
    expect(
      matchingIgnoreRule(rules, { repositoryId: "repo_b", ruleId: "github-pat", path: "test/x.js" }),
    ).toBeNull();
    expect(matchingIgnoreRule(rules, { repositoryId: "repo_b", ruleId: "jwt", path: "src/a.ts" })?.id).toBe(
      "r2",
    );
    const finding = (paths: string[]) => ({
      repositoryId: "repo_a",
      ruleId: "github-pat",
      places: paths.map((path) => ({ path })),
    });
    expect(ignoringRule(rules, finding(["test/a.js", "test/b/c.js"]))?.id).toBe("r1");
    // The same value also in src/: still a leak.
    expect(ignoringRule(rules, finding(["test/a.js", "src/config.js"]))).toBeNull();
    expect(ignoringRule(rules, finding([]))).toBeNull();
  });
});
