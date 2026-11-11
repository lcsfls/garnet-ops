/**
 * Secret and sensitive-file scanning (ADR 0049). Pure and free of Node APIs, so the web app can use the rule names and
 * severities too.
 *
 * gitleaks (MIT) finds the secrets. GarnetOps always hands it this configuration: gitleaks' own default rules plus rules for
 * files that never belong in a repository. A repository's own `.gitleaks.toml`, `.gitleaksignore` and `gitleaks:allow` comments
 * are never honoured: whoever can commit could otherwise hide a secret from the check.
 *
 * The value of a secret never leaves the scanner: `redactGitleaksReport` (secret-fingerprint.ts) replaces it by its SHA-256 and
 * drops the matched text and the author before the report is handed over. `parseGitleaksReport` turns that digest into a keyed
 * fingerprint through a callback. Nothing here stores, logs or returns a value, a matched line or the author of a commit.
 */

export const SECRET_SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type SecretSeverity = (typeof SECRET_SEVERITIES)[number];

/** A rule of GarnetOps' own, written into the gitleaks configuration. `path` and `regex` are Go (RE2) regular expressions. */
export interface SensitiveFileRule {
  id: string;
  description: string;
  severity: SecretSeverity;
  /** The file path the rule is about (always set: these rules are about files that do not belong in a repository). */
  path: string;
  /** If set, the file only counts when its content matches too (for files that are fine without credentials). */
  regex?: string;
  /** Paths the rule never fires on (templates and examples). */
  allowPaths?: string[];
}

/** Templates and examples are meant to be committed. */
const EXAMPLES = String.raw`(?i)\.(?:example|sample|template|tmpl|dist|defaults?|schema|ci|test)$`;

export const SENSITIVE_FILE_RULES: readonly SensitiveFileRule[] = [
  {
    id: "garnetops-env-file",
    description: "Environment file with values",
    severity: "high",
    path: String.raw`(?:^|/)\.env(?:\.[A-Za-z0-9_-]+)?$`,
    // Only when a variable has a value: an empty template is fine.
    regex: String.raw`(?m)^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*["']?[^\s"'#]{4,}`,
    allowPaths: [EXAMPLES],
  },
  {
    id: "garnetops-ssh-private-key-file",
    description: "SSH private key file",
    severity: "critical",
    path: String.raw`(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?$`,
  },
  {
    id: "garnetops-putty-private-key-file",
    description: "PuTTY private key file",
    severity: "critical",
    path: String.raw`(?i)\.ppk$`,
  },
  {
    id: "garnetops-keystore-file",
    description: "Key store with private keys",
    severity: "high",
    path: String.raw`(?i)\.(?:p12|pfx|jks|keystore|bks)$`,
  },
  {
    id: "garnetops-git-credentials-file",
    description: "Stored Git or network credentials",
    severity: "critical",
    path: String.raw`(?:^|/)(?:\.git-credentials|\.netrc|_netrc)$`,
  },
  {
    id: "garnetops-npmrc-token",
    description: "npm registry token in .npmrc",
    severity: "high",
    path: String.raw`(?:^|/)\.npmrc$`,
    regex: String.raw`(?m)_(?:authToken|auth|password)\s*=\s*[^\s$]{6,}`,
  },
  {
    id: "garnetops-pypirc-password",
    description: "Package index password in .pypirc",
    severity: "high",
    path: String.raw`(?:^|/)\.pypirc$`,
    regex: String.raw`(?m)^\s*password\s*[=:]\s*\S{4,}`,
  },
  {
    id: "garnetops-docker-auth",
    description: "Container registry credentials",
    severity: "high",
    path: String.raw`(?:^|/)(?:\.dockercfg|\.docker/config\.json)$`,
    regex: String.raw`"auth"\s*:\s*"[A-Za-z0-9+/=]{8,}"`,
  },
  {
    id: "garnetops-kubeconfig-credentials",
    description: "Kubernetes configuration with credentials",
    severity: "critical",
    path: String.raw`(?:^|/)(?:kubeconfig(?:\.ya?ml)?|\.kube/config)$`,
    regex: String.raw`(?m)^\s*(?:client-key-data|token|password)\s*:\s*\S{8,}`,
  },
  {
    id: "garnetops-terraform-state",
    description: "Terraform state (holds resource secrets in plain text)",
    severity: "high",
    path: String.raw`(?i)\.tfstate(?:\.backup)?$`,
  },
  {
    id: "garnetops-database-dump",
    description: "Database dump or database file",
    severity: "medium",
    path: String.raw`(?i)\.(?:dump|sql\.gz|sql\.bz2|sql\.xz|sqlite3?)$`,
  },
  {
    id: "garnetops-htpasswd",
    description: "Password file of a web server",
    severity: "medium",
    path: String.raw`(?:^|/)\.htpasswd$`,
  },
  {
    id: "garnetops-wordpress-db-password",
    description: "WordPress database password",
    severity: "high",
    path: String.raw`(?:^|/)wp-config\.php$`,
    regex: String.raw`define\(\s*['"]DB_PASSWORD['"]\s*,\s*['"][^'"]{4,}['"]`,
  },
  {
    id: "garnetops-ai-agent-local-settings",
    description: "Personal AI agent settings (may hold commands with credentials)",
    severity: "high",
    path: String.raw`(?:^|/)\.claude/settings\.local\.json$`,
  },
];

/** gitleaks rules for access to infrastructure, code or the software supply chain: a leak lets someone change what runs. */
const CRITICAL_PREFIXES = [
  "private-key",
  "age-secret-key",
  "aws-",
  "azure-",
  "gcp-",
  "alibaba-",
  "yandex-aws-",
  "digitalocean-",
  "cloudflare-",
  "github-",
  "gitlab-",
  "bitbucket-client-secret",
  "npm-access-token",
  "pypi-upload-token",
  "rubygems-api-token",
  "nuget-config-password",
  "clojars-api-token",
  "artifactory-",
  "jfrog-",
  "hashicorp-tf-",
  "vault-",
  "kubernetes-secret-yaml",
  "openshift-user-token",
  "heroku-",
  "flyio-access-token",
  "netlify-access-token",
  "pulumi-api-token",
  "doppler-api-token",
  "1password-",
  "droneci-access-token",
  "travisci-access-token",
  "octopus-deploy-api-key",
];

/** gitleaks rules that guess by shape or entropy, or match a token form many projects use in examples. */
const GUESSING = new Set(["generic-api-key", "jwt", "jwt-base64", "curl-auth-header", "curl-auth-user"]);

/** gitleaks rules for identifiers that are public by design (client ids, publishable keys). */
const PUBLIC_IDENTIFIER = /-(?:client-id|access-id|api-id|pub-key|pub-api-key|public-key)$/;

const OWN = new Map(SENSITIVE_FILE_RULES.map((r) => [r.id, r]));

/** The fixed severity of a rule: plain, never moved by anything else (ADR 0049). */
export function secretSeverity(ruleId: string): SecretSeverity {
  const own = OWN.get(ruleId);
  if (own) return own.severity;
  if (PUBLIC_IDENTIFIER.test(ruleId)) return "low";
  if (GUESSING.has(ruleId)) return "medium";
  if (CRITICAL_PREFIXES.some((p) => ruleId === p || (p.endsWith("-") && ruleId.startsWith(p))))
    return "critical";
  return "high";
}

/** Whether the rule is about a file that should not be in the repository at all, rather than a value inside a file. */
export function isSensitiveFileRule(ruleId: string): boolean {
  return OWN.has(ruleId);
}

/** A literal TOML string: rule texts are fixed in code, so a `'''` inside one is a bug. */
function literal(value: string): string {
  if (value.includes("'''")) throw new Error(`gitleaks config: ''' in ${value}`);
  return `'''${value}'''`;
}

/** The configuration GarnetOps hands gitleaks: its default rules, plus the rules above. */
export function gitleaksConfig(): string {
  const lines = ['title = "GarnetOps secret scanning (ADR 0049)"', "", "[extend]", "useDefault = true"];
  for (const rule of SENSITIVE_FILE_RULES) {
    lines.push(
      "",
      "[[rules]]",
      `id = "${rule.id}"`,
      `description = "${rule.description.replace(/"/g, "'")}"`,
    );
    lines.push(`path = ${literal(rule.path)}`);
    if (rule.regex) lines.push(`regex = ${literal(rule.regex)}`);
    if (rule.allowPaths?.length) {
      lines.push("[[rules.allowlists]]", `paths = [${rule.allowPaths.map(literal).join(", ")}]`);
    }
  }
  return `${lines.join("\n")}\n`;
}

/** The arguments every gitleaks run gets, besides the mode and the target: our configuration, never the repository's. */
export function gitleaksArgs(opts: { configPath: string; emptyDir: string; reportPath: string }): string[] {
  return [
    "--no-banner",
    "--no-color",
    "--log-level",
    "error",
    "--config",
    opts.configPath,
    // An empty directory instead of the repository's .gitleaksignore, and its gitleaks:allow comments ignored.
    "--gitleaks-ignore-path",
    opts.emptyDir,
    "--ignore-gitleaks-allow",
    "--max-target-megabytes",
    "5",
    "--max-decode-depth",
    "2",
    "--report-format",
    "json",
    "--report-path",
    opts.reportPath,
    "--exit-code",
    "0",
  ];
}

/** One place where a secret or a sensitive file was found. No value, no matched text, no author. */
export interface SecretHit {
  ruleId: string;
  severity: SecretSeverity;
  /** The path inside the repository, relative, cleaned. */
  path: string;
  /** The first line, or null for a rule about the whole file. */
  line: number | null;
  /** Set in history scans: the commit that added it, and its date. */
  commit: string | null;
  committedAt: string | null;
  /** The keyed fingerprint of the secret (or of rule and path for file rules); computed by the caller's `fingerprint`. */
  fingerprint: string;
}

export interface ParsedSecretReport {
  hits: SecretHit[];
  /** More hits than `maxHits`: the rest are counted, not kept. */
  dropped: number;
  /** Entries that did not have the expected shape. */
  invalid: number;
}

export const SECRET_LIMITS = {
  /** Hits kept per scan. */
  maxHits: 2000,
  /** The report is refused above this size. */
  maxReportBytes: 32 * 1024 * 1024,
  maxPathLength: 500,
} as const;

// biome-ignore lint/suspicious/noControlCharactersInRegex: removing control characters is the point
const CONTROL = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g;

/**
 * The path as the repository has it: relative to the scanned directory, `/`-separated, without control or bidirectional
 * characters. Null when it is not a path inside the repository.
 */
export function cleanSecretPath(raw: string, root: string): string | null {
  let path = raw.replace(/\\/g, "/");
  const base = root.replace(/\\/g, "/").replace(/\/+$/, "");
  if (base && path.startsWith(`${base}/`)) path = path.slice(base.length + 1);
  path = path.replace(CONTROL, "").replace(/^\.\//, "");
  if (!path || path.startsWith("/") || path.length > SECRET_LIMITS.maxPathLength) return null;
  if (path.split("/").some((part) => part === ".." || part === "")) return null;
  return path;
}

const RULE_ID = /^[a-z0-9][a-z0-9-]{1,79}$/;
const COMMIT = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;

/**
 * Reads gitleaks' JSON report as `redactGitleaksReport` left it. `fingerprint` receives the rule, the value's SHA-256 (empty for
 * file rules) and the path, and returns the keyed fingerprint; the digest is not kept anywhere else. Hits with the same rule, fingerprint, path and line count once.
 */
export function parseGitleaksReport(
  text: string,
  opts: {
    root: string;
    fingerprint: (ruleId: string, secret: string, path: string) => string;
    maxHits?: number;
  },
): ParsedSecretReport {
  const maxHits = opts.maxHits ?? SECRET_LIMITS.maxHits;
  if (text.length > SECRET_LIMITS.maxReportBytes) throw new Error("secret report too large");
  const trimmed = text.trim();
  const data: unknown = trimmed === "" ? [] : JSON.parse(trimmed);
  if (!Array.isArray(data)) throw new Error("secret report is not a list");
  const hits: SecretHit[] = [];
  const seen = new Set<string>();
  let dropped = 0;
  let invalid = 0;
  for (const entry of data as unknown[]) {
    const e = entry as Record<string, unknown> | null;
    const ruleId = typeof e?.RuleID === "string" ? e.RuleID : "";
    const file = typeof e?.File === "string" ? e.File : "";
    if (!RULE_ID.test(ruleId) || !file) {
      invalid += 1;
      continue;
    }
    const path = cleanSecretPath(file, opts.root);
    if (!path) {
      invalid += 1;
      continue;
    }
    const startLine = typeof e?.StartLine === "number" && Number.isInteger(e.StartLine) ? e.StartLine : 0;
    const commit = typeof e?.Commit === "string" && COMMIT.test(e.Commit) ? e.Commit : null;
    const date =
      typeof e?.Date === "string" && !Number.isNaN(Date.parse(e.Date))
        ? new Date(e.Date).toISOString()
        : null;
    const secret = typeof e?.Secret === "string" && !isSensitiveFileRule(ruleId) ? e.Secret : "";
    const fingerprint = opts.fingerprint(ruleId, secret, path);
    const line = startLine > 0 ? startLine : null;
    const key = `${ruleId}\u0000${fingerprint}\u0000${path}\u0000${line ?? ""}\u0000${commit ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (hits.length >= maxHits) {
      dropped += 1;
      continue;
    }
    hits.push({
      ruleId,
      severity: secretSeverity(ruleId),
      path,
      line,
      commit,
      committedAt: commit ? date : null,
      fingerprint,
    });
  }
  return { hits, dropped, invalid };
}

/* -------------------------------------------------------------------------------------------------------------------------- */
/* Ignore rules (ADR 0049, addendum): kept in GarnetOps by admins, never read from the repository.                            */
/* -------------------------------------------------------------------------------------------------------------------------- */

/** An admin's rule that sets aside what matches it. At least one of `pathPattern` and `ruleId` is set. */
export interface SecretIgnoreRule {
  id: string;
  /** Null: every repository of the organisation. */
  repositoryId: string | null;
  /** A glob over the path inside the repository: `*` within a folder, `**` across folders, `?` one character. */
  pathPattern: string | null;
  ruleId: string | null;
}

export const IGNORE_PATTERN_MAX = 200;

/** Why a path pattern is not acceptable, or null. Patterns are relative, plain and short; no regular expressions. */
export function ignorePatternProblem(pattern: string): string | null {
  if (!pattern.trim()) return "empty";
  if (pattern.length > IGNORE_PATTERN_MAX) return "too-long";
  if (pattern.startsWith("/") || pattern.split("/").some((part) => part === ".." || part === ""))
    return "not-relative";
  // biome-ignore lint/suspicious/noControlCharactersInRegex: refusing control characters is the point
  if (/[\u0000-\u001f\u007f[\]{}\\]/.test(pattern)) return "characters";
  // A rule that matches every path of every repository would switch the check off; it must name something.
  if (/^[*?/]*$/.test(pattern)) return "everything";
  return null;
}

/** The glob as a regular expression anchored to the whole path. Linear: no nested quantifiers. */
export function ignorePatternRegExp(pattern: string): RegExp {
  let out = "";
  for (let i = 0; i < pattern.length; i += 1) {
    const c = pattern[i] as string;
    if (c === "*" && pattern[i + 1] === "*") {
      // "**/" matches no folder or any number of them; a final "**" matches the rest.
      if (pattern[i + 2] === "/") {
        out += "(?:[^/]+/)*";
        i += 2;
      } else {
        out += ".*";
        i += 1;
      }
    } else if (c === "*") out += "[^/]*";
    else if (c === "?") out += "[^/]";
    else out += c.replace(/[.+^$()|]/g, "\\$&");
  }
  return new RegExp(`^${out}$`);
}

/** The first rule that covers this place of this rule's finding in this repository, or null. */
export function matchingIgnoreRule(
  rules: readonly SecretIgnoreRule[],
  hit: { repositoryId: string; ruleId: string; path: string },
): SecretIgnoreRule | null {
  for (const rule of rules) {
    if (rule.repositoryId && rule.repositoryId !== hit.repositoryId) continue;
    if (rule.ruleId && rule.ruleId !== hit.ruleId) continue;
    if (rule.pathPattern && !ignorePatternRegExp(rule.pathPattern).test(hit.path)) continue;
    return rule;
  }
  return null;
}

/**
 * The rule that sets a whole finding aside: only when every place it is known at (files and history) is covered. A secret that
 * is also anywhere else stays open: the rule is about a place, and the same value elsewhere is still a leak.
 */
export function ignoringRule(
  rules: readonly SecretIgnoreRule[],
  finding: { repositoryId: string; ruleId: string; places: readonly { path: string }[] },
): SecretIgnoreRule | null {
  if (finding.places.length === 0 || rules.length === 0) return null;
  let first: SecretIgnoreRule | null = null;
  for (const place of finding.places) {
    const rule = matchingIgnoreRule(rules, {
      repositoryId: finding.repositoryId,
      ruleId: finding.ruleId,
      path: place.path,
    });
    if (!rule) return null;
    first ??= rule;
  }
  return first;
}
