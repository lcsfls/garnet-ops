/**
 * Database schema. Migrations are generated from this file with drizzle-kit
 * and are forward-only (expand/contract, AGENTS.md rule 2).
 */
import {
  bigint,
  bigserial,
  boolean,
  date,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  real,
  text,
  time,
  timestamp,
  uniqueIndex,
} from "drizzle-orm/pg-core";

const createdAt = () => timestamp("created_at", { withTimezone: true }).notNull().defaultNow();
const updatedAt = () => timestamp("updated_at", { withTimezone: true }).notNull().defaultNow();

/* -------------------------------------------------------------------------- */
/* better-auth tables (core + two-factor plugin)                               */
/* -------------------------------------------------------------------------- */

export const user = pgTable("user", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  image: text("image"),
  twoFactorEnabled: boolean("two_factor_enabled").notNull().default(false),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const session = pgTable(
  "session",
  {
    id: text("id").primaryKey(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    token: text("token").notNull().unique(),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [index("session_user_idx").on(t.userId)],
);

export const account = pgTable(
  "account",
  {
    id: text("id").primaryKey(),
    accountId: text("account_id").notNull(),
    providerId: text("provider_id").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    accessToken: text("access_token"),
    refreshToken: text("refresh_token"),
    idToken: text("id_token"),
    accessTokenExpiresAt: timestamp("access_token_expires_at", { withTimezone: true }),
    refreshTokenExpiresAt: timestamp("refresh_token_expires_at", { withTimezone: true }),
    scope: text("scope"),
    password: text("password"),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [index("account_user_idx").on(t.userId)],
);

export const verification = pgTable("verification", {
  id: text("id").primaryKey(),
  identifier: text("identifier").notNull(),
  value: text("value").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  createdAt: createdAt(),
  updatedAt: updatedAt(),
});

export const twoFactor = pgTable(
  "two_factor",
  {
    id: text("id").primaryKey(),
    secret: text("secret").notNull(),
    backupCodes: text("backup_codes").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    verified: boolean("verified").notNull().default(true),
    /** Lockout after repeated wrong codes; managed by better-auth's two-factor plugin. */
    failedVerificationCount: integer("failed_verification_count").notNull().default(0),
    lockedUntil: timestamp("locked_until", { withTimezone: true }),
  },
  (t) => [index("two_factor_user_idx").on(t.userId)],
);

export const rateLimit = pgTable("rate_limit", {
  id: text("id").primaryKey(),
  key: text("key").notNull().unique(),
  count: integer("count").notNull(),
  lastRequest: bigint("last_request", { mode: "number" }).notNull(),
});

/* -------------------------------------------------------------------------- */
/* Organisations and access                                                    */
/* -------------------------------------------------------------------------- */

export const organization = pgTable("organization", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  /** Nightly scan of every repository (ADR 0005: local time plus an explicit IANA zone). */
  scanScheduleEnabled: boolean("scan_schedule_enabled").notNull().default(true),
  /** Local wall-clock time of the nightly scan, "HH:MM:SS". Outside 02:00-03:00 by default. */
  scanLocalTime: time("scan_local_time").notNull().default("04:00:00"),
  scanTimeZone: text("scan_time_zone").notNull().default("UTC"),
  createdAt: createdAt(),
});

/**
 * One row per organisation and intended local date of a nightly run. The
 * primary key is the de-duplication key of ADR 0005: a repeated autumn hour
 * cannot start a second run, and a skipped spring hour is caught up later.
 */
export const scanScheduleRun = pgTable(
  "scan_schedule_run",
  {
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    localDate: date("local_date").notNull(),
    queuedScans: integer("queued_scans").notNull(),
    createdAt: createdAt(),
  },
  (t) => [primaryKey({ columns: [t.organizationId, t.localDate] })],
);

export const membership = pgTable(
  "membership",
  {
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    role: text("role", { enum: ["owner", "admin", "member", "viewer"] }).notNull(),
    createdAt: createdAt(),
  },
  (t) => [primaryKey({ columns: [t.organizationId, t.userId] }), index("membership_user_idx").on(t.userId)],
);

/* -------------------------------------------------------------------------- */
/* Secrets vault (ADR 0004). Plaintext never touches the database.             */
/* -------------------------------------------------------------------------- */

export const secret = pgTable(
  "secret",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    purpose: text("purpose", {
      enum: ["forge-token", "ssh-private-key", "ai-api-key", "netbird-token", "smtp-password"],
    }).notNull(),
    /** SealedSecret JSON from @garnetops/core/vault. */
    sealed: jsonb("sealed").notNull(),
    vaultKeyId: text("vault_key_id").notNull(),
    createdBy: text("created_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
  },
  (t) => [index("secret_org_idx").on(t.organizationId), index("secret_vault_key_idx").on(t.vaultKeyId)],
);

/* -------------------------------------------------------------------------- */
/* Repositories, scans and findings                                            */
/* -------------------------------------------------------------------------- */

export const repository = pgTable(
  "repository",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    url: text("url").notNull(),
    branch: text("branch"),
    authKind: text("auth_kind", { enum: ["none", "https-token", "ssh-deploy-key"] }).notNull(),
    secretId: text("secret_id").references(() => secret.id, { onDelete: "set null" }),
    /** Public half of a generated deploy key, shown so the user can add it to the forge. */
    deployPublicKey: text("deploy_public_key"),
    /**
     * SSH host keys pinned on first contact (known_hosts lines). Every later clone requires
     * exactly these keys; only an admin can clear them.
     */
    sshKnownHosts: text("ssh_known_hosts"),
    sshKnownHostsPinnedAt: timestamp("ssh_known_hosts_pinned_at", { withTimezone: true }),
    /** The user who connected the repository and owns its credential. */
    ownerUserId: text("owner_user_id").references(() => user.id, { onDelete: "set null" }),
    lastScanId: text("last_scan_id"),
    lastScanAt: timestamp("last_scan_at", { withTimezone: true }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    index("repository_org_idx").on(t.organizationId, t.name, t.id),
    uniqueIndex("repository_org_url_uq").on(t.organizationId, t.url),
  ],
);

export const scan = pgTable(
  "scan",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    repositoryId: text("repository_id")
      .notNull()
      .references(() => repository.id, { onDelete: "cascade" }),
    state: text("state", { enum: ["queued", "running", "succeeded", "failed"] }).notNull(),
    trigger: text("trigger", { enum: ["manual", "schedule", "webhook", "ci"] }).notNull(),
    requestedBy: text("requested_by").references(() => user.id, { onDelete: "set null" }),
    branch: text("branch"),
    /**
     * Ref a gate check asked for (a branch, tag or pull request ref such as
     * "refs/pull/12/head"); null scans the repository's configured branch.
     */
    ref: text("ref"),
    /** Commit the gate check expects; the scan fails if the fetched ref points elsewhere. */
    expectedSha: text("expected_sha"),
    commitSha: text("commit_sha"),
    packageCount: integer("package_count"),
    /** Counts of findings by severity seen in this scan. */
    severityCounts: jsonb("severity_counts").$type<Record<string, number>>(),
    newFindings: integer("new_findings"),
    resolvedFindings: integer("resolved_findings"),
    scannerVersions: jsonb("scanner_versions").$type<Record<string, string>>(),
    vulnDbBuiltAt: timestamp("vuln_db_built_at", { withTimezone: true }),
    /** Short, user-safe error message. Never contains secrets or raw scanner output. */
    error: text("error"),
    startedAt: timestamp("started_at", { withTimezone: true }),
    finishedAt: timestamp("finished_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (t) => [
    index("scan_org_created_idx").on(t.organizationId, t.createdAt, t.id),
    index("scan_repo_created_idx").on(t.repositoryId, t.createdAt),
  ],
);

/* -------------------------------------------------------------------------- */
/* Quality gates (ADR 0008)                                                    */
/* -------------------------------------------------------------------------- */

/** A rule's mode for one organisation. A missing row means the rule's default (never "block"). */
export const gateRule = pgTable(
  "gate_rule",
  {
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    rule: text("rule").notNull(),
    mode: text("mode", { enum: ["off", "report", "block"] }).notNull(),
    /** Rule settings, e.g. { deniedLicenses: ["AGPL-3.0-only"] }. */
    config: jsonb("config").$type<Record<string, unknown>>(),
    updatedBy: text("updated_by").references(() => user.id, { onDelete: "set null" }),
    updatedAt: updatedAt(),
  },
  (t) => [primaryKey({ columns: [t.organizationId, t.rule] })],
);

/** CI token for one repository: can request a gate check and read its result, nothing else. */
export const gateToken = pgTable(
  "gate_token",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    repositoryId: text("repository_id")
      .notNull()
      .references(() => repository.id, { onDelete: "cascade" }),
    /** SHA-256 of the token; the token itself is shown once and never stored. */
    tokenHash: text("token_hash").notNull(),
    /** First characters of the token, so people can tell their tokens apart. */
    prefix: text("prefix").notNull(),
    label: text("label").notNull(),
    createdBy: text("created_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (t) => [uniqueIndex("gate_token_hash_uq").on(t.tokenHash), index("gate_token_repo_idx").on(t.repositoryId)],
);

/** The gate result of one scan, evaluated once with the modes in force at that time. */
export const gateRun = pgTable(
  "gate_run",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    repositoryId: text("repository_id")
      .notNull()
      .references(() => repository.id, { onDelete: "cascade" }),
    scanId: text("scan_id")
      .notNull()
      .references(() => scan.id, { onDelete: "cascade" }),
    result: text("result", { enum: ["passed", "notes", "blocked"] }).notNull(),
    /** Matching count and mode per rule, e.g. { "critical-fixable": { count: 2, mode: "block" } }. */
    matches: jsonb("matches").$type<Record<string, { count: number; mode: string }>>().notNull(),
    createdAt: createdAt(),
  },
  (t) => [
    uniqueIndex("gate_run_scan_uq").on(t.scanId),
    index("gate_run_org_created_idx").on(t.organizationId, t.createdAt, t.id),
    index("gate_run_repo_created_idx").on(t.repositoryId, t.createdAt),
  ],
);

/** Global vulnerability catalogue, shared by all organisations. */
export const vulnerability = pgTable("vulnerability", {
  id: text("id").primaryKey(),
  namespace: text("namespace"),
  severity: text("severity").notNull(),
  cvssScore: real("cvss_score"),
  cvssVector: text("cvss_vector"),
  description: text("description"),
  urls: jsonb("urls").$type<string[]>(),
  /** Related IDs, e.g. a GHSA that aliases a CVE. */
  aliases: jsonb("aliases").$type<string[]>(),
  knownExploited: boolean("known_exploited").notNull().default(false),
  epss: real("epss"),
  /** When the advisory was first published and last changed, from the local vulnerability database. */
  publishedAt: timestamp("published_at", { withTimezone: true }),
  modifiedAt: timestamp("modified_at", { withTimezone: true }),
  updatedAt: updatedAt(),
});

export const finding = pgTable(
  "finding",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    repositoryId: text("repository_id")
      .notNull()
      .references(() => repository.id, { onDelete: "cascade" }),
    vulnerabilityId: text("vulnerability_id")
      .notNull()
      .references(() => vulnerability.id),
    /** Deduplication key: repository + vulnerability + package name + package type. */
    dedupKey: text("dedup_key").notNull(),
    packageName: text("package_name").notNull(),
    packageVersion: text("package_version").notNull(),
    packageType: text("package_type").notNull(),
    packagePurl: text("package_purl"),
    fixedIn: jsonb("fixed_in").$type<string[]>(),
    fixState: text("fix_state"),
    locations: jsonb("locations").$type<string[]>(),
    severity: text("severity").notNull(),
    /** Numeric rank of `severity` (5 = critical) for sorting worst first. */
    severityRank: integer("severity_rank").notNull(),
    state: text("state", { enum: ["open", "accepted", "resolved"] }).notNull(),
    acceptedReason: text("accepted_reason"),
    acceptedUntil: timestamp("accepted_until", { withTimezone: true }),
    acceptedBy: text("accepted_by").references(() => user.id, { onDelete: "set null" }),
    firstSeenScanId: text("first_seen_scan_id").notNull(),
    lastSeenScanId: text("last_seen_scan_id").notNull(),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull(),
    resolvedAt: timestamp("resolved_at", { withTimezone: true }),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex("finding_dedup_uq").on(t.organizationId, t.dedupKey),
    // Default list order: worst first, then most recently seen.
    index("finding_list_idx").on(t.organizationId, t.state, t.severityRank, t.lastSeenAt, t.id),
    index("finding_repo_idx").on(t.repositoryId, t.state),
    index("finding_vuln_idx").on(t.vulnerabilityId),
  ],
);

/**
 * Current package inventory of each repository: every package of its latest successful scan
 * (syft SBOM), replaced as a whole on the next one. Answers "which repository contains X".
 */
export const repositoryPackage = pgTable(
  "repository_package",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    repositoryId: text("repository_id")
      .notNull()
      .references(() => repository.id, { onDelete: "cascade" }),
    scanId: text("scan_id").notNull(),
    name: text("name").notNull(),
    version: text("version").notNull(),
    type: text("type").notNull(),
    purl: text("purl"),
    locations: jsonb("locations").$type<string[]>(),
    licenses: jsonb("licenses").$type<string[]>(),
  },
  (t) => [
    // List order and name search across the organisation.
    index("repository_package_list_idx").on(t.organizationId, t.name, t.version, t.id),
    index("repository_package_repo_idx").on(t.repositoryId),
  ],
);

/* -------------------------------------------------------------------------- */
/* AI triage                                                                   */
/* -------------------------------------------------------------------------- */

export const aiSettings = pgTable("ai_settings", {
  organizationId: text("organization_id")
    .primaryKey()
    .references(() => organization.id, { onDelete: "cascade" }),
  baseUrl: text("base_url").notNull(),
  model: text("model").notNull(),
  apiKeySecretId: text("api_key_secret_id").references(() => secret.id, { onDelete: "set null" }),
  /** How much code context the model may see: "excerpt" or "metadata". */
  contextPolicy: text("context_policy", { enum: ["excerpt", "metadata"] })
    .notNull()
    .default("excerpt"),
  updatedBy: text("updated_by").references(() => user.id, { onDelete: "set null" }),
  updatedAt: updatedAt(),
});

export const chatThread = pgTable(
  "chat_thread",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    findingId: text("finding_id")
      .notNull()
      .references(() => finding.id, { onDelete: "cascade" }),
    createdBy: text("created_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
  },
  (t) => [index("chat_thread_finding_idx").on(t.findingId, t.createdAt)],
);

export const chatMessage = pgTable(
  "chat_message",
  {
    id: text("id").primaryKey(),
    threadId: text("thread_id")
      .notNull()
      .references(() => chatThread.id, { onDelete: "cascade" }),
    role: text("role", { enum: ["user", "assistant"] }).notNull(),
    content: text("content").notNull(),
    status: text("status", { enum: ["complete", "streaming", "stopped", "failed"] }).notNull(),
    model: text("model"),
    promptTokens: integer("prompt_tokens"),
    completionTokens: integer("completion_tokens"),
    latencyMs: integer("latency_ms"),
    /** The context the model received, so users can see exactly what it saw. */
    context: jsonb("context"),
    createdBy: text("created_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
  },
  (t) => [index("chat_message_thread_idx").on(t.threadId, t.createdAt, t.id)],
);

/* -------------------------------------------------------------------------- */
/* Audit log: append-only                                                       */
/* -------------------------------------------------------------------------- */

export const auditLog = pgTable(
  "audit_log",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    organizationId: text("organization_id").references(() => organization.id, { onDelete: "set null" }),
    actorUserId: text("actor_user_id").references(() => user.id, { onDelete: "set null" }),
    action: text("action").notNull(),
    targetType: text("target_type"),
    targetId: text("target_id"),
    ip: text("ip"),
    data: jsonb("data"),
    createdAt: createdAt(),
    /**
     * Entries copied from another system's journal (the update sidecar: "updater") carry
     * its name and event id; the unique index makes the copy exactly-once. Null for the
     * app's own entries (NULLs never collide in a unique index).
     */
    source: text("source"),
    eventId: text("event_id"),
  },
  (t) => [
    index("audit_org_created_idx").on(t.organizationId, t.createdAt),
    uniqueIndex("audit_source_event_idx").on(t.source, t.eventId),
  ],
);

/** How far the update sidecar's journal has been copied into the audit log (one row). */
export const updaterJournalCursor = pgTable("updater_journal_cursor", {
  id: integer("id").primaryKey(),
  lastEventId: text("last_event_id").notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});
