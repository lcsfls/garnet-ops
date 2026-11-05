/**
 * The SSH server check of the host agent (ADR 0037, addendum "SSH server"): from what the agent read on the host (which SSH server,
 * its package, the C library, and the global values of a few settings in sshd_config), a small, fixed set of configuration
 * findings ("SSH hardening"). Pure and side-effect free, so the API computes it when a host page is read.
 *
 * Every rule is report-only: it never changes a vulnerability finding, a count, a grade or a gate (AGENTS.md rule 2). The one rule
 * that depends on a vulnerability, *sshole* (CVE-2026-123158), takes the distribution's verdict from the vulnerability database as
 * authoritative and falls back to the upstream OpenSSH version only while the database does not know the flaw yet.
 */

/** OpenSSH's own defaults (upstream). A distribution can build OpenSSH with others; GarnetOps only reads files. */
export const SSHD_DEFAULTS = {
  passwordAuthentication: "yes",
  kbdInteractiveAuthentication: "yes",
  permitRootLogin: "prohibit-password",
  usePam: "no",
  permitEmptyPasswords: "no",
  pubkeyAuthentication: "yes",
} as const;
export type SshdSettingName = keyof typeof SSHD_DEFAULTS;
export const SSHD_SETTING_NAMES = Object.keys(SSHD_DEFAULTS) as SshdSettingName[];

/** The effective global value of a setting, whether it is the default, and the distinct values Match blocks set. */
export interface SshdSetting {
  value: string;
  default: boolean;
  match: string[];
}

export const SSHD_SKIP_REASONS = [
  "unreadable",
  "too-large",
  "not-regular",
  "outside",
  "limit",
  "depth",
] as const;
export type SshdSkipReason = (typeof SSHD_SKIP_REASONS)[number];

/** What the agent reports in the inventory field `sshd` (see sshdFactsSchema in ./agent.ts). */
export interface SshdFacts {
  server: "openssh" | "dropbear" | "none";
  package: { name: string; version: string } | null;
  libc: "musl" | "glibc" | "unknown";
  /** Whether sshd is linked against libpam; without it UsePAM has no effect. Null when unknown. */
  pamLinked: boolean | null;
  /** Null for Dropbear and hosts without an SSH server. `read` is false when sshd_config itself could not be read. */
  config: {
    read: boolean;
    problem: string | null;
    files: string[];
    skipped: { path: string; reason: SshdSkipReason }[];
    settings: Record<SshdSettingName, SshdSetting> | null;
  } | null;
}

/** The flaw with a configuration-dependent risk: OpenSSH without PAM on musl, password logins of 257 to 1024 bytes. */
export const SSHOLE_CVE = "CVE-2026-123158";
/** The first upstream release with the fix. Distributions may backport it into older versions. */
export const SSHOLE_FIXED_UPSTREAM = "10.6p2";
/** Advisories whose presence in the vulnerability database the worker reports, because a rule depends on it. */
export const WATCHED_ADVISORIES = [SSHOLE_CVE] as const;

/** "1:9.6p1-3ubuntu13.5", "10.0_p1-r9", "8.7p1-38.el9" → [major, minor, portable release]; null when it is not that shape. */
export function parseOpenSshVersion(version: string): [number, number, number] | null {
  const m = /^(?:\d+:)?(\d+)\.(\d+)(?:_?p(\d+))?/.exec(version.trim());
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), m[3] === undefined ? 0 : Number(m[3])];
}

/** Compares two OpenSSH versions by their upstream part only (not the distribution's release). Null when either cannot be read. */
export function compareOpenSshVersions(a: string, b: string): number | null {
  const x = parseOpenSshVersion(a);
  const y = parseOpenSshVersion(b);
  if (!x || !y) return null;
  for (let i = 0; i < 3; i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d !== 0) return Math.sign(d);
  }
  return 0;
}

/** Whether a host package finding is the *sshole* flaw on an OpenSSH package (openssh, openssh-server, openssh-client-...). */
export function isSsholeFinding(f: { vulnerabilityId: string; packageName: string }): boolean {
  return f.vulnerabilityId.toUpperCase() === SSHOLE_CVE && f.packageName.startsWith("openssh");
}

/** What the rules look at, in plain terms. Null where it cannot be told from the facts. */
export interface SshdEffective {
  passwordAuthentication: { global: boolean; inMatch: boolean } | null;
  permitRootLogin: { global: boolean; inMatch: boolean } | null;
  permitEmptyPasswords: { global: boolean; inMatch: boolean } | null;
  /** PAM is used only when sshd is built with it and UsePAM is yes. */
  pam: boolean | null;
}

const yes = (v: string | undefined) => v === "yes";

export function sshdEffective(facts: SshdFacts): SshdEffective {
  const settings = facts.server === "openssh" && facts.config?.read ? facts.config.settings : null;
  const flag = (s: SshdSetting | undefined) =>
    s ? { global: yes(s.value), inMatch: s.match.some(yes) } : null;
  return {
    passwordAuthentication: flag(settings?.passwordAuthentication),
    permitRootLogin: flag(settings?.permitRootLogin),
    permitEmptyPasswords: flag(settings?.permitEmptyPasswords),
    pam: facts.pamLinked === false ? false : settings ? yes(settings.usePam.value) : null,
  };
}

export const SSHD_RULES = ["sshole", "root-login", "empty-passwords", "password-authentication"] as const;
export type SshdRule = (typeof SSHD_RULES)[number];

/** Fixed severities: the rules are plain, and their rating does not move with anything else. */
export const SSHD_RULE_SEVERITY: Record<SshdRule, "critical" | "high" | "medium"> = {
  sshole: "critical",
  "root-login": "high",
  "empty-passwords": "high",
  "password-authentication": "medium",
};

export interface SshdFinding {
  rule: SshdRule;
  severity: "critical" | "high" | "medium";
  /** "global": for every connection; "match": only in Match blocks (some users, groups or addresses). */
  scope: "global" | "match";
  /** sshole only: whether the vulnerability database's finding or the upstream version showed the package affected. */
  basis?: "finding" | "version";
}

/** What decides whether the installed OpenSSH has the *sshole* flaw. */
export interface SsholeContext {
  /** The host has an open finding for CVE-2026-123158 on an OpenSSH package. */
  cveFinding: boolean;
  /** Whether the local vulnerability database knows the CVE at all; null when that cannot be told. */
  cveKnown: boolean | null;
}

/**
 * Whether the installed OpenSSH has the flaw: the vulnerability database decides once it knows the CVE (a distribution's
 * backported fix then shows as no finding); before that, the upstream version below 10.6p2 does. Null when neither can tell.
 */
export function ssholeAffected(
  facts: SshdFacts,
  ctx: SsholeContext,
): { affected: boolean; basis: "finding" | "version" } | null {
  if (ctx.cveFinding) return { affected: true, basis: "finding" };
  if (ctx.cveKnown === true) return { affected: false, basis: "finding" };
  if (facts.server !== "openssh" || !facts.package) return null;
  const order = compareOpenSshVersions(facts.package.version, SSHOLE_FIXED_UPSTREAM);
  return order === null ? null : { affected: order < 0, basis: "version" };
}

const scopeOf = (flag: { global: boolean; inMatch: boolean } | null): "global" | "match" | null =>
  !flag ? null : flag.global ? "global" : flag.inMatch ? "match" : null;

/** The configuration findings of one host, worst first. Empty without an OpenSSH server or a readable sshd_config. */
export function sshdFindings(facts: SshdFacts, ctx: SsholeContext): SshdFinding[] {
  const e = sshdEffective(facts);
  const out: SshdFinding[] = [];
  const add = (rule: SshdRule, scope: "global" | "match" | null, extra: Partial<SshdFinding> = {}) => {
    if (scope) out.push({ rule, severity: SSHD_RULE_SEVERITY[rule], scope, ...extra });
  };
  const password = scopeOf(e.passwordAuthentication);
  const affected = ssholeAffected(facts, ctx);
  if (facts.libc === "musl" && e.pam === false && affected?.affected) {
    add("sshole", password, { basis: affected.basis });
  }
  add("root-login", scopeOf(e.permitRootLogin));
  add("empty-passwords", scopeOf(e.permitEmptyPasswords));
  add("password-authentication", password);
  return out;
}

export const SSHOLE_SAFE_REASONS = [
  "no-openssh-server",
  "dropbear",
  "glibc",
  "pam",
  "password-authentication-off",
] as const;
export type SsholeSafeReason = (typeof SSHOLE_SAFE_REASONS)[number];

/**
 * Why the *sshole* flaw cannot be used on this host as it is configured, for the note next to its vulnerability finding. Empty when
 * it can, or when the facts cannot tell (an older agent, an unreadable sshd_config, an unknown C library). The finding itself and
 * its severity stay as the vulnerability database has them.
 */
export function ssholeSafeReasons(facts: SshdFacts | null): SsholeSafeReason[] {
  if (!facts) return [];
  if (facts.server === "dropbear") return ["dropbear"];
  if (facts.server === "none") return ["no-openssh-server"];
  const reasons: SsholeSafeReason[] = [];
  if (facts.libc === "glibc") reasons.push("glibc");
  const e = sshdEffective(facts);
  if (e.pam === true) reasons.push("pam");
  if (e.passwordAuthentication && !e.passwordAuthentication.global && !e.passwordAuthentication.inMatch) {
    reasons.push("password-authentication-off");
  }
  return reasons;
}
