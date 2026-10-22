/**
 * Database schema. Migrations are generated from this file with drizzle-kit
 * and are forward-only (expand/contract, AGENTS.md rule 2).
 */
import { sql } from "drizzle-orm";
import {
  bigint,
  bigserial,
  boolean,
  customType,
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

/** A one-time invitation into an organisation (ADR 0009). Only the token's hash is stored. */
export const invitation = pgTable(
  "invitation",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    /** Lower-case address the invitation is for; the account gets exactly this address. */
    email: text("email").notNull(),
    role: text("role", { enum: ["owner", "admin", "member", "viewer"] }).notNull(),
    tokenHash: text("token_hash").notNull(),
    invitedBy: text("invited_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    acceptedAt: timestamp("accepted_at", { withTimezone: true }),
    acceptedUserId: text("accepted_user_id").references(() => user.id, { onDelete: "set null" }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (t) => [
    uniqueIndex("invitation_token_hash_uq").on(t.tokenHash),
    index("invitation_org_created_idx").on(t.organizationId, t.createdAt),
  ],
);

/* -------------------------------------------------------------------------- */
/* Notifications (ADR 0010)                                                    */
/* -------------------------------------------------------------------------- */

/** Where notifications go. Credentials (webhook URL, SMTP password, Graph secret) are sealed in `secret`. */
export const notificationChannel = pgTable(
  "notification_channel",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    kind: text("kind", { enum: ["webhook", "smtp", "graph"] }).notNull(),
    /** Webhooks only: "generic", "discord" or "slack". */
    format: text("format"),
    language: text("language").notNull().default("en"),
    events: jsonb("events").$type<string[]>().notNull(),
    /** Settings that are not secret: hosts, ports, sender, recipients, the webhook's host for display. */
    config: jsonb("config").$type<Record<string, unknown>>().notNull(),
    secretId: text("secret_id").references(() => secret.id, { onDelete: "set null" }),
    enabled: boolean("enabled").notNull().default(true),
    createdBy: text("created_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [index("notification_channel_org_idx").on(t.organizationId)],
);

export const notificationDelivery = pgTable(
  "notification_delivery",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    channelId: text("channel_id")
      .notNull()
      .references(() => notificationChannel.id, { onDelete: "cascade" }),
    event: text("event").notNull(),
    status: text("status", { enum: ["sent", "failed"] }).notNull(),
    /** A short, safe reason ("timeout", "refused address", "HTTP 404"); never a response body. */
    error: text("error"),
    createdAt: createdAt(),
  },
  (t) => [index("notification_delivery_channel_idx").on(t.channelId, t.createdAt)],
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
      enum: [
        "forge-token",
        "ssh-private-key",
        "ai-api-key",
        "netbird-token",
        "smtp-password",
        "webhook-url",
        "graph-client-secret",
        "host-ssh-key",
        "proxmox-token",
        "forge-write-token",
        "wazuh-api-password",
        "wazuh-indexer-password",
        "osint-api-key",
      ],
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
/* Fix proposals and fix pull requests (ADR 0014)                              */
/* -------------------------------------------------------------------------- */

/**
 * The dependency manifests of a repository's last scan of its configured branch (package.json,
 * go.mod, requirements*.txt …), replaced as a whole on the next one. Holds what the Fix
 * proposals page needs without cloning again: which packages a manifest declares directly,
 * and the git blob id of the file, so that a pull request refuses to edit a file that
 * changed after the scan.
 */
export const repositoryManifest = pgTable(
  "repository_manifest",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    repositoryId: text("repository_id")
      .notNull()
      .references(() => repository.id, { onDelete: "cascade" }),
    scanId: text("scan_id").notNull(),
    /** Repository-relative path without a leading slash. */
    path: text("path").notNull(),
    /** Ecosystem: npm, pypi, composer, go or cargo. */
    kind: text("kind").notNull(),
    /** Git blob id (SHA-1) of the file as scanned. */
    blobSha: text("blob_sha").notNull(),
    size: integer("size").notNull(),
    /** Declared dependencies: name, section, requirement, indirect, dev, blocked (a refusal code). */
    dependencies: jsonb("dependencies")
      .$type<
        { name: string; section: string; spec: string; indirect: boolean; dev: boolean; blocked?: string }[]
      >()
      .notNull(),
    createdAt: createdAt(),
  },
  (t) => [
    index("repository_manifest_repo_idx").on(t.repositoryId),
    uniqueIndex("repository_manifest_path_uq").on(t.repositoryId, t.path),
  ],
);

/**
 * The opt-in to fix pull requests for one repository: a write token of its own, sealed in the
 * vault (purpose "forge-write-token"), never the read credential. Deleting the row (and the
 * secret) switches the feature off. The API seals; only the worker opens.
 */
export const repositoryWriteAccess = pgTable("repository_write_access", {
  repositoryId: text("repository_id")
    .primaryKey()
    .references(() => repository.id, { onDelete: "cascade" }),
  organizationId: text("organization_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
  /** No secret, no write access: deleting the secret removes the row. */
  secretId: text("secret_id")
    .notNull()
    .references(() => secret.id, { onDelete: "cascade" }),
  forgeKind: text("forge_kind", { enum: ["github", "gitea", "forgejo"] }).notNull(),
  /** The only address the token is ever sent to, e.g. https://api.github.com or https://git.example.com/api/v1. */
  apiBaseUrl: text("api_base_url").notNull(),
  enabledBy: text("enabled_by").references(() => user.id, { onDelete: "set null" }),
  enabledAt: timestamp("enabled_at", { withTimezone: true }).notNull().defaultNow(),
  /** Result of the worker's last check of the token: "unchecked" until it ran. */
  status: text("status", { enum: ["unchecked", "ok", "failed"] })
    .notNull()
    .default("unchecked"),
  /** A short, safe code when the check failed (never a response body). */
  statusReason: text("status_reason"),
  /** "broad-token": the forge says the token can reach more than this repository. */
  warning: text("warning"),
  checkedAt: timestamp("checked_at", { withTimezone: true }),
});

/** One fix pull request, from the request to its end on the forge. */
export const fixPr = pgTable(
  "fix_pr",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    repositoryId: text("repository_id")
      .notNull()
      .references(() => repository.id, { onDelete: "cascade" }),
    /** The proposal this pull request carries out (see proposalKey in packages/core/src/fix-prs.ts). */
    proposalKey: text("proposal_key").notNull(),
    ecosystem: text("ecosystem").notNull(),
    packageName: text("package_name").notNull(),
    fromVersion: text("from_version").notNull(),
    toVersion: text("to_version").notNull(),
    majorUpgrade: boolean("major_upgrade").notNull().default(false),
    manifestPath: text("manifest_path").notNull(),
    /** The manifest's git blob id from the scan; the edit is refused if the file on the forge differs. */
    expectedBlobSha: text("expected_blob_sha").notNull(),
    severity: text("severity").notNull(),
    vulnerabilityIds: jsonb("vulnerability_ids").$type<string[]>().notNull(),
    state: text("state", { enum: ["queued", "running", "open", "merged", "closed", "failed"] }).notNull(),
    /** A safe code why it failed, or why the last status refresh did not work. */
    reason: text("reason"),
    branch: text("branch"),
    baseBranch: text("base_branch"),
    prNumber: integer("pr_number"),
    /** Built by us from the repository address and the number, never taken from the forge's answer. */
    prUrl: text("pr_url"),
    requestedBy: text("requested_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
    openedAt: timestamp("opened_at", { withTimezone: true }),
    closedAt: timestamp("closed_at", { withTimezone: true }),
    lastCheckedAt: timestamp("last_checked_at", { withTimezone: true }),
  },
  (t) => [
    index("fix_pr_org_created_idx").on(t.organizationId, t.createdAt, t.id),
    index("fix_pr_repo_idx").on(t.repositoryId, t.state),
    index("fix_pr_state_idx").on(t.state, t.lastCheckedAt),
    // One live pull request per change: a second click cannot open a duplicate.
    uniqueIndex("fix_pr_active_uq")
      .on(t.repositoryId, t.proposalKey)
      .where(sql`${t.state} in ('queued', 'running', 'open')`),
  ],
);

/* -------------------------------------------------------------------------- */
/* Servers: agentless inventory over SSH (ADR 0011)                            */
/* -------------------------------------------------------------------------- */

/**
 * The SSH key pair an organisation's worker uses to read its servers. The worker generates it;
 * the private half is sealed in the vault (`secret`, purpose "host-ssh-key") and never leaves
 * the platform, the public half is stored in clear and rendered into the host setup script.
 * Rotation keeps the old row as "retired" until every server accepts the new key (later).
 */
export const hostAccessKey = pgTable(
  "host_access_key",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    /** One line in authorized_keys format, `ssh-ed25519 AAAA… comment`. */
    publicKey: text("public_key").notNull(),
    /** `SHA256:…` fingerprint of the public key. */
    fingerprint: text("fingerprint").notNull(),
    secretId: text("secret_id").references(() => secret.id, { onDelete: "set null" }),
    state: text("state", { enum: ["active", "retired"] })
      .notNull()
      .default("active"),
    /** The source addresses last used for a setup script, offered again next time. */
    allowedSource: text("allowed_source"),
    createdAt: createdAt(),
    retiredAt: timestamp("retired_at", { withTimezone: true }),
  },
  (t) => [uniqueIndex("host_access_key_active_uq").on(t.organizationId).where(sql`${t.state} = 'active'`)],
);

/** A one-time download link for the host setup script. Only the token's hash is stored. */
export const hostSetupLink = pgTable(
  "host_setup_link",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    accessKeyId: text("access_key_id")
      .notNull()
      .references(() => hostAccessKey.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    allowedSource: text("allowed_source").notNull(),
    /** SHA-256 of the script the link was made for; the download is refused if it would differ. */
    scriptSha256: text("script_sha256").notNull(),
    createdBy: text("created_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    usedAt: timestamp("used_at", { withTimezone: true }),
    usedIp: text("used_ip"),
  },
  (t) => [
    uniqueIndex("host_setup_link_token_hash_uq").on(t.tokenHash),
    index("host_setup_link_org_idx").on(t.organizationId, t.createdAt),
  ],
);

export const host = pgTable(
  "host",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    /** Host name or IP address, validated and normalised (packages/core/src/hosts.ts). */
    address: text("address").notNull(),
    port: integer("port").notNull().default(22),
    sshUser: text("ssh_user").notNull().default("garnetops"),
    /**
     * Where the server came from: "manual", "csv" today; "proxmox" and "wazuh" later link a
     * server to a record of that system through `sourceRef` without a schema change.
     */
    source: text("source").notNull().default("manual"),
    sourceRef: text("source_ref"),

    /**
     * Host key pinning (trust on first use, confirmed by an admin). `pending`: no key confirmed
     * yet. `confirmed`: inventory runs against exactly this key. `changed`: the server presented
     * another key (kept in the candidate columns); inventory stops until an admin confirms it.
     */
    hostKeyStatus: text("host_key_status", { enum: ["pending", "confirmed", "changed"] })
      .notNull()
      .default("pending"),
    hostKeyType: text("host_key_type"),
    /** Base64 key blob, as in known_hosts. */
    hostKey: text("host_key"),
    hostKeyFingerprint: text("host_key_fingerprint"),
    hostKeyConfirmedAt: timestamp("host_key_confirmed_at", { withTimezone: true }),
    hostKeyConfirmedBy: text("host_key_confirmed_by").references(() => user.id, { onDelete: "set null" }),
    candidateKeyType: text("candidate_key_type"),
    candidateKey: text("candidate_key"),
    candidateKeyFingerprint: text("candidate_key_fingerprint"),
    candidateKeySeenAt: timestamp("candidate_key_seen_at", { withTimezone: true }),

    /** From the last successful inventory. */
    osId: text("os_id"),
    osVersionId: text("os_version_id"),
    osName: text("os_name"),
    kernel: text("kernel"),
    arch: text("arch"),
    packageCount: integer("package_count"),
    pendingUpdates: integer("pending_updates"),
    securityUpdates: integer("security_updates"),
    lastInventoryAt: timestamp("last_inventory_at", { withTimezone: true }),
    /** Short, user-safe reason of the last failure (packages/core/src/host-errors.ts); null if the last run worked. */
    lastError: text("last_error"),

    createdBy: text("created_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex("host_org_address_port_uq").on(t.organizationId, t.address, t.port),
    index("host_org_name_idx").on(t.organizationId, t.name, t.id),
    uniqueIndex("host_source_ref_uq")
      .on(t.organizationId, t.source, t.sourceRef)
      .where(sql`${t.sourceRef} is not null`),
  ],
);

/** Current packages of a server: the whole list of its last successful inventory, replaced as a whole. */
export const hostPackage = pgTable(
  "host_package",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    hostId: text("host_id")
      .notNull()
      .references(() => host.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    version: text("version").notNull(),
    arch: text("arch"),
    type: text("type", { enum: ["deb", "rpm", "apk"] }).notNull(),
    /** Source package (deb), source RPM (rpm) or origin (apk), if known. */
    origin: text("origin"),
    originVersion: text("origin_version"),
    /** The version an update would install; null if up to date. */
    upgradableTo: text("upgradable_to"),
    securityUpdate: boolean("security_update").notNull().default(false),
  },
  (t) => [
    index("host_package_host_idx").on(t.hostId, t.name, t.version, t.id),
    // "Where does package X run": the inventory search across servers (ROADMAP).
    index("host_package_org_name_idx").on(t.organizationId, t.name),
  ],
);

export const hostInventoryRun = pgTable(
  "host_inventory_run",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    hostId: text("host_id")
      .notNull()
      .references(() => host.id, { onDelete: "cascade" }),
    state: text("state", { enum: ["queued", "running", "succeeded", "failed"] }).notNull(),
    trigger: text("trigger", { enum: ["manual", "schedule", "setup"] }).notNull(),
    requestedBy: text("requested_by").references(() => user.id, { onDelete: "set null" }),
    packageCount: integer("package_count"),
    pendingUpdates: integer("pending_updates"),
    newFindings: integer("new_findings"),
    resolvedFindings: integer("resolved_findings"),
    severityCounts: jsonb("severity_counts").$type<Record<string, number>>(),
    scannerVersions: jsonb("scanner_versions").$type<Record<string, string>>(),
    vulnDbBuiltAt: timestamp("vuln_db_built_at", { withTimezone: true }),
    /** Short, user-safe error message. Never contains output of the server. */
    error: text("error"),
    startedAt: timestamp("started_at", { withTimezone: true }),
    finishedAt: timestamp("finished_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (t) => [
    index("host_inventory_run_host_idx").on(t.hostId, t.createdAt, t.id),
    index("host_inventory_run_org_idx").on(t.organizationId, t.createdAt, t.id),
  ],
);

/** A vulnerability matched against a package of a server: same shape as `finding` for repositories. */
export const hostFinding = pgTable(
  "host_finding",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    hostId: text("host_id")
      .notNull()
      .references(() => host.id, { onDelete: "cascade" }),
    vulnerabilityId: text("vulnerability_id")
      .notNull()
      .references(() => vulnerability.id),
    /** Deduplication key: host + vulnerability + package type + package name. */
    dedupKey: text("dedup_key").notNull(),
    packageName: text("package_name").notNull(),
    packageVersion: text("package_version").notNull(),
    packageType: text("package_type").notNull(),
    packagePurl: text("package_purl"),
    fixedIn: jsonb("fixed_in").$type<string[]>(),
    fixState: text("fix_state"),
    severity: text("severity").notNull(),
    /** Numeric rank of `severity` (5 = critical) for sorting worst first. */
    severityRank: integer("severity_rank").notNull(),
    state: text("state", { enum: ["open", "resolved"] }).notNull(),
    firstSeenRunId: text("first_seen_run_id").notNull(),
    lastSeenRunId: text("last_seen_run_id").notNull(),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull(),
    resolvedAt: timestamp("resolved_at", { withTimezone: true }),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex("host_finding_dedup_uq").on(t.organizationId, t.dedupKey),
    index("host_finding_host_idx").on(t.hostId, t.state, t.severityRank, t.id),
    index("host_finding_org_idx").on(t.organizationId, t.state, t.severityRank, t.lastSeenAt, t.id),
    index("host_finding_vuln_idx").on(t.vulnerabilityId),
  ],
);

/* -------------------------------------------------------------------------- */
/* Proxmox VE (ADR 0012): read-only inventory of clusters, nodes and guests     */
/* -------------------------------------------------------------------------- */

/**
 * A connection to one Proxmox VE cluster (or stand-alone node). The API token secret is sealed
 * in `secret` (purpose proxmox-token); the API only seals it, the worker opens it. The
 * certificate is pinned on first contact like an SSH host key: `certStatus` is `pending` until an
 * admin confirms the fingerprint of the candidate, `confirmed` while every request matches the
 * pin, and `changed` when the server presented another certificate (sync stops until an admin
 * confirms the new one).
 */
export const proxmoxCluster = pgTable(
  "proxmox_cluster",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    /** Normalised `https://host:port`; host and port are kept apart for connecting. */
    apiUrl: text("api_url").notNull(),
    host: text("host").notNull(),
    port: integer("port").notNull().default(8006),
    /** `user@realm!tokenid`: not secret. */
    tokenId: text("token_id").notNull(),
    secretId: text("secret_id").references(() => secret.id, { onDelete: "set null" }),
    enabled: boolean("enabled").notNull().default(true),

    certStatus: text("cert_status", { enum: ["pending", "confirmed", "changed"] })
      .notNull()
      .default("pending"),
    /** SHA-256 of the pinned leaf certificate, upper-case hex pairs separated by colons. */
    certFingerprint: text("cert_fingerprint"),
    certSubject: text("cert_subject"),
    certIssuer: text("cert_issuer"),
    certValidFrom: timestamp("cert_valid_from", { withTimezone: true }),
    certValidTo: timestamp("cert_valid_to", { withTimezone: true }),
    certConfirmedAt: timestamp("cert_confirmed_at", { withTimezone: true }),
    certConfirmedBy: text("cert_confirmed_by").references(() => user.id, { onDelete: "set null" }),
    candidateFingerprint: text("candidate_fingerprint"),
    candidateSubject: text("candidate_subject"),
    candidateIssuer: text("candidate_issuer"),
    candidateValidFrom: timestamp("candidate_valid_from", { withTimezone: true }),
    candidateValidTo: timestamp("candidate_valid_to", { withTimezone: true }),
    /** The candidate also verifies against the worker's public CA store (informational; the pin is always applied). */
    candidateCaTrusted: boolean("candidate_ca_trusted"),
    candidateSeenAt: timestamp("candidate_seen_at", { withTimezone: true }),

    /** Privileges of the token beyond *.Audit, as read from /access/permissions at the last sync. */
    extraPrivileges: jsonb("extra_privileges").$type<string[]>().notNull().default([]),
    /** The extra privileges an admin has acknowledged; a sync runs only if it covers every extra privilege. */
    acknowledgedPrivileges: jsonb("acknowledged_privileges").$type<string[]>().notNull().default([]),
    privilegesAcknowledgedAt: timestamp("privileges_acknowledged_at", { withTimezone: true }),
    privilegesAcknowledgedBy: text("privileges_acknowledged_by").references(() => user.id, {
      onDelete: "set null",
    }),
    permissionsCheckedAt: timestamp("permissions_checked_at", { withTimezone: true }),

    /** From the last successful sync. */
    version: text("version"),
    /** The cluster's own name; null for a stand-alone node. */
    clusterName: text("cluster_name"),
    quorate: boolean("quorate"),
    /** False when the token may not list backups, so "no recent backup" cannot be told. */
    backupsReadable: boolean("backups_readable").notNull().default(false),
    lastSyncAt: timestamp("last_sync_at", { withTimezone: true }),
    /** Short, user-safe reason of the last failure (packages/core/src/proxmox-errors.ts); null if the last run worked. */
    lastError: text("last_error"),

    createdBy: text("created_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [
    uniqueIndex("proxmox_cluster_org_name_uq").on(t.organizationId, t.name),
    uniqueIndex("proxmox_cluster_org_endpoint_uq").on(t.organizationId, t.host, t.port),
  ],
);

export const proxmoxNode = pgTable(
  "proxmox_node",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    clusterId: text("cluster_id")
      .notNull()
      .references(() => proxmoxCluster.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    online: boolean("online").notNull(),
    cpu: real("cpu"),
    cpus: integer("cpus"),
    mem: bigint("mem", { mode: "number" }),
    maxMem: bigint("max_mem", { mode: "number" }),
    disk: bigint("disk", { mode: "number" }),
    maxDisk: bigint("max_disk", { mode: "number" }),
    uptime: bigint("uptime", { mode: "number" }),
    pveVersion: text("pve_version"),
    kernel: text("kernel"),
    /** Packages the node's own last `apt update` found upgradable; null if not readable. */
    pendingUpdates: integer("pending_updates"),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull(),
  },
  (t) => [uniqueIndex("proxmox_node_cluster_name_uq").on(t.clusterId, t.name)],
);

export const proxmoxGuest = pgTable(
  "proxmox_guest",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    clusterId: text("cluster_id")
      .notNull()
      .references(() => proxmoxCluster.id, { onDelete: "cascade" }),
    vmid: integer("vmid").notNull(),
    type: text("type", { enum: ["qemu", "lxc"] }).notNull(),
    name: text("name").notNull(),
    node: text("node").notNull(),
    status: text("status", { enum: ["running", "stopped", "paused", "other"] }).notNull(),
    /** When GarnetOps first saw the guest in this status (Proxmox does not tell how long it has been stopped). */
    statusSince: timestamp("status_since", { withTimezone: true }).notNull(),
    cpu: real("cpu"),
    cpus: integer("cpus"),
    mem: bigint("mem", { mode: "number" }),
    maxMem: bigint("max_mem", { mode: "number" }),
    disk: bigint("disk", { mode: "number" }),
    maxDisk: bigint("max_disk", { mode: "number" }),
    uptime: bigint("uptime", { mode: "number" }),
    ostype: text("ostype"),
    tags: jsonb("tags").$type<string[]>().notNull().default([]),
    template: boolean("template").notNull().default(false),
    haState: text("ha_state"),
    /** An enabled backup job includes the guest; null if the jobs are not readable. */
    inBackupJob: boolean("in_backup_job"),
    lastBackupAt: timestamp("last_backup_at", { withTimezone: true }),
    snapshotCount: integer("snapshot_count"),
    newestSnapshotAt: timestamp("newest_snapshot_at", { withTimezone: true }),
    oldestSnapshotAt: timestamp("oldest_snapshot_at", { withTimezone: true }),
    /** Addresses from the guest agent, the container's interfaces or its static configuration; may be empty. */
    ips: jsonb("ips").$type<string[]>().notNull().default([]),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull(),
  },
  (t) => [
    uniqueIndex("proxmox_guest_cluster_vmid_uq").on(t.clusterId, t.vmid),
    index("proxmox_guest_org_name_idx").on(t.organizationId, t.name, t.id),
  ],
);

export const proxmoxStorage = pgTable(
  "proxmox_storage",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    clusterId: text("cluster_id")
      .notNull()
      .references(() => proxmoxCluster.id, { onDelete: "cascade" }),
    node: text("node").notNull(),
    name: text("name").notNull(),
    type: text("type"),
    content: jsonb("content").$type<string[]>().notNull().default([]),
    shared: boolean("shared").notNull().default(false),
    status: text("status"),
    used: bigint("used", { mode: "number" }),
    total: bigint("total", { mode: "number" }),
  },
  (t) => [uniqueIndex("proxmox_storage_cluster_uq").on(t.clusterId, t.node, t.name)],
);

export const proxmoxSyncRun = pgTable(
  "proxmox_sync_run",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    clusterId: text("cluster_id")
      .notNull()
      .references(() => proxmoxCluster.id, { onDelete: "cascade" }),
    state: text("state", { enum: ["queued", "running", "succeeded", "failed"] }).notNull(),
    trigger: text("trigger", { enum: ["manual", "schedule", "setup"] }).notNull(),
    requestedBy: text("requested_by").references(() => user.id, { onDelete: "set null" }),
    nodeCount: integer("node_count"),
    guestCount: integer("guest_count"),
    requestCount: integer("request_count"),
    /** Codes of things that could not be read but did not stop the sync (packages/core/src/proxmox-errors.ts). */
    warnings: jsonb("warnings").$type<string[]>().notNull().default([]),
    /** Short, user-safe error message. Never contains output of the Proxmox server. */
    error: text("error"),
    startedAt: timestamp("started_at", { withTimezone: true }),
    finishedAt: timestamp("finished_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (t) => [
    index("proxmox_sync_run_cluster_idx").on(t.clusterId, t.createdAt, t.id),
    index("proxmox_sync_run_org_idx").on(t.organizationId, t.createdAt, t.id),
  ],
);

/* -------------------------------------------------------------------------- */
/* Wazuh (ADR 0015): read-only XDR integration                                 */
/* -------------------------------------------------------------------------- */

/**
 * The connection to a customer-run Wazuh (one per organisation today; the tables carry the
 * connection id so more can follow without a migration of the data). The two service users'
 * passwords live in `wazuh_endpoint` as vault references; the API seals them, only the worker
 * opens them. Nothing here is a credential.
 */
export const wazuhConnection = pgTable(
  "wazuh_connection",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    /** The customer's Wazuh dashboard, shown as an external link; never requested by GarnetOps. */
    dashboardUrl: text("dashboard_url"),
    /** The address agents use to reach the manager (`WAZUH_MANAGER` in the enrollment commands). */
    enrollmentHost: text("enrollment_host"),
    enabled: boolean("enabled").notNull().default(true),

    /** From the last successful sync: the adapter chosen by the manager's version. */
    adapter: text("adapter", { enum: ["wazuh4", "wazuh5"] }),
    managerVersion: text("manager_version"),
    indexerVersion: text("indexer_version"),

    /** Privileges of the two service users beyond reading (packages/core/src/wazuh.ts), found at the last sync. */
    extraPrivileges: jsonb("extra_privileges").$type<string[]>().notNull().default([]),
    /** The extra privileges an admin has acknowledged; a sync reads data only if it covers every extra privilege. */
    acknowledgedPrivileges: jsonb("acknowledged_privileges").$type<string[]>().notNull().default([]),
    privilegesAcknowledgedAt: timestamp("privileges_acknowledged_at", { withTimezone: true }),
    privilegesAcknowledgedBy: text("privileges_acknowledged_by").references(() => user.id, {
      onDelete: "set null",
    }),
    permissionsCheckedAt: timestamp("permissions_checked_at", { withTimezone: true }),

    lastSyncAt: timestamp("last_sync_at", { withTimezone: true }),
    /** Short, user-safe reason of the last failure (packages/core/src/wazuh-errors.ts); null if the last run worked. */
    lastError: text("last_error"),

    createdBy: text("created_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
    updatedAt: updatedAt(),
  },
  (t) => [uniqueIndex("wazuh_connection_org_uq").on(t.organizationId)],
);

/**
 * One of the two endpoints of a connection: the manager REST API (JWT, port 55000) or the
 * indexer (port 9200). The certificate is pinned on first contact like an SSH host key
 * (trust `pin`), or verified against a certificate authority the admin uploaded (trust `ca`,
 * public data, stored in clear).
 */
export const wazuhEndpoint = pgTable(
  "wazuh_endpoint",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    connectionId: text("connection_id")
      .notNull()
      .references(() => wazuhConnection.id, { onDelete: "cascade" }),
    kind: text("kind", { enum: ["manager", "indexer"] }).notNull(),
    /** Normalised `https://host:port`; host and port are kept apart for connecting. */
    apiUrl: text("api_url").notNull(),
    host: text("host").notNull(),
    port: integer("port").notNull(),
    username: text("username").notNull(),
    secretId: text("secret_id").references(() => secret.id, { onDelete: "set null" }),

    trustMode: text("trust_mode", { enum: ["pin", "ca"] })
      .notNull()
      .default("pin"),
    /** PEM of the uploaded certificate authority (public); only used when trustMode is `ca`. */
    caPem: text("ca_pem"),
    certStatus: text("cert_status", { enum: ["pending", "confirmed", "changed"] })
      .notNull()
      .default("pending"),
    certFingerprint: text("cert_fingerprint"),
    certSubject: text("cert_subject"),
    certIssuer: text("cert_issuer"),
    certValidFrom: timestamp("cert_valid_from", { withTimezone: true }),
    certValidTo: timestamp("cert_valid_to", { withTimezone: true }),
    certConfirmedAt: timestamp("cert_confirmed_at", { withTimezone: true }),
    certConfirmedBy: text("cert_confirmed_by").references(() => user.id, { onDelete: "set null" }),
    candidateFingerprint: text("candidate_fingerprint"),
    candidateSubject: text("candidate_subject"),
    candidateIssuer: text("candidate_issuer"),
    candidateValidFrom: timestamp("candidate_valid_from", { withTimezone: true }),
    candidateValidTo: timestamp("candidate_valid_to", { withTimezone: true }),
    /** The candidate also verifies against the worker's public CA store (informational; the pin is always applied). */
    candidateCaTrusted: boolean("candidate_ca_trusted"),
    candidateSeenAt: timestamp("candidate_seen_at", { withTimezone: true }),
    /** Short, user-safe reason of the last failure of the certificate check. */
    lastError: text("last_error"),
    updatedAt: updatedAt(),
  },
  (t) => [uniqueIndex("wazuh_endpoint_connection_kind_uq").on(t.connectionId, t.kind)],
);

/** An agent as the manager lists it. Replaced by every sync; the link to a server survives. */
export const wazuhAgent = pgTable(
  "wazuh_agent",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    connectionId: text("connection_id")
      .notNull()
      .references(() => wazuhConnection.id, { onDelete: "cascade" }),
    /** The manager's id, "000" for the manager itself. */
    agentId: text("agent_id").notNull(),
    name: text("name").notNull(),
    ip: text("ip"),
    osName: text("os_name"),
    osVersion: text("os_version"),
    osPlatform: text("os_platform"),
    arch: text("arch"),
    version: text("version"),
    status: text("status", {
      enum: ["active", "disconnected", "never_connected", "pending", "unknown"],
    }).notNull(),
    lastKeepAliveAt: timestamp("last_keep_alive_at", { withTimezone: true }),
    groups: jsonb("groups").$type<string[]>().notNull().default([]),
    registeredAt: timestamp("registered_at", { withTimezone: true }),
    isManager: boolean("is_manager").notNull().default(false),
    /** Open vulnerability states per severity from the indexer; null if the indexer could not be read. */
    vulnCritical: integer("vuln_critical"),
    vulnHigh: integer("vuln_high"),
    vulnMedium: integer("vuln_medium"),
    vulnLow: integer("vuln_low"),

    /** The server this agent was confirmed to be. An admin sets it; a sync never does. */
    hostId: text("host_id").references(() => host.id, { onDelete: "set null" }),
    linkedAt: timestamp("linked_at", { withTimezone: true }),
    linkedBy: text("linked_by").references(() => user.id, { onDelete: "set null" }),
    /** What the sync thinks this agent is; shown for an admin to confirm or ignore. */
    suggestedHostId: text("suggested_host_id").references(() => host.id, { onDelete: "set null" }),
    suggestionReason: text("suggestion_reason", { enum: ["address", "name", "hostname"] }),

    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull(),
  },
  (t) => [
    uniqueIndex("wazuh_agent_connection_agent_uq").on(t.connectionId, t.agentId),
    uniqueIndex("wazuh_agent_host_uq").on(t.hostId).where(sql`${t.hostId} is not null`),
    index("wazuh_agent_org_name_idx").on(t.organizationId, t.name, t.id),
  ],
);

/** The latest alert aggregates of a connection (packages/core/src/wazuh.ts, `Snapshot`): numbers only. */
export const wazuhSnapshot = pgTable("wazuh_snapshot", {
  connectionId: text("connection_id")
    .primaryKey()
    .references(() => wazuhConnection.id, { onDelete: "cascade" }),
  organizationId: text("organization_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
  data: jsonb("data").notNull(),
  syncedAt: timestamp("synced_at", { withTimezone: true }).notNull(),
});

/** A small bounded sample of the latest file integrity events. Replaced as a whole by every sync. */
export const wazuhFimEvent = pgTable(
  "wazuh_fim_event",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    connectionId: text("connection_id")
      .notNull()
      .references(() => wazuhConnection.id, { onDelete: "cascade" }),
    at: timestamp("at", { withTimezone: true }).notNull(),
    agentId: text("agent_id").notNull(),
    agentName: text("agent_name").notNull(),
    /** Plain text written by whoever changed the file. Shown as text, never as a link, never sent to the model. */
    path: text("path").notNull(),
    event: text("event", { enum: ["added", "modified", "deleted", "other"] }).notNull(),
    ruleLevel: integer("rule_level"),
  },
  (t) => [index("wazuh_fim_event_conn_idx").on(t.connectionId, t.at)],
);

/**
 * Source addresses of authentication failures and attacks, top 100 per window with their counts,
 * first and last alert and the agents they attacked: the data of the attack overview (ADR 0016).
 * Source addresses can be personal data, so they are replaced by every sync and deleted after the
 * retention period (default 90 days) whatever happens.
 */
export const wazuhSourceIp = pgTable(
  "wazuh_source_ip",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    connectionId: text("connection_id")
      .notNull()
      .references(() => wazuhConnection.id, { onDelete: "cascade" }),
    window: text("time_window", { enum: ["24h", "7d", "30d"] }).notNull(),
    ip: text("ip").notNull(),
    count: integer("count").notNull(),
    /** Rule groups that raised the alerts, from a fixed list of authentication and attack groups. */
    groups: jsonb("groups").$type<string[]>().notNull().default([]),
    /** When the sync wrote this row; the retention period counts from here (ADR 0016). */
    seenAt: timestamp("seen_at", { withTimezone: true }).notNull(),
    /** Time of the first and the last alert of this address in the window, from the indexer. */
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
    /** The agents this address attacked most (id, name, alerts), at most 5. */
    agents: jsonb("agents").$type<{ agentId: string; name: string; count: number }[]>().notNull().default([]),
  },
  (t) => [uniqueIndex("wazuh_source_ip_uq").on(t.connectionId, t.window, t.ip)],
);

/**
 * Attack numbers per window (ADR 0016): all attack and authentication-failure alerts, distinct
 * sources, the targeted agents, and the previous period (with its source addresses, for the
 * change in countries). Replaced window by window by the sync, like `wazuh_source_ip`.
 */
export const wazuhAttackWindow = pgTable(
  "wazuh_attack_window",
  {
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    connectionId: text("connection_id")
      .notNull()
      .references(() => wazuhConnection.id, { onDelete: "cascade" }),
    window: text("time_window", { enum: ["24h", "7d", "30d"] }).notNull(),
    attackAlerts: integer("attack_alerts").notNull(),
    distinctSources: integer("distinct_sources").notNull(),
    agents: jsonb("agents").$type<{ agentId: string; name: string; count: number }[]>().notNull().default([]),
    /** Null when the previous period could not be read. */
    previousAttackAlerts: integer("previous_attack_alerts"),
    previousDistinctSources: integer("previous_distinct_sources"),
    previousSources: jsonb("previous_sources").$type<{ ip: string; count: number }[]>().notNull().default([]),
    readAt: timestamp("read_at", { withTimezone: true }).notNull(),
  },
  (t) => [primaryKey({ columns: [t.connectionId, t.window] })],
);

export const wazuhSyncRun = pgTable(
  "wazuh_sync_run",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    connectionId: text("connection_id")
      .notNull()
      .references(() => wazuhConnection.id, { onDelete: "cascade" }),
    state: text("state", { enum: ["queued", "running", "succeeded", "failed"] }).notNull(),
    trigger: text("trigger", { enum: ["manual", "schedule", "setup"] }).notNull(),
    requestedBy: text("requested_by").references(() => user.id, { onDelete: "set null" }),
    agentCount: integer("agent_count"),
    requestCount: integer("request_count"),
    /** Codes of things that could not be read but did not stop the sync (packages/core/src/wazuh-errors.ts). */
    warnings: jsonb("warnings").$type<string[]>().notNull().default([]),
    /** Short, user-safe error message. Never contains output of Wazuh. */
    error: text("error"),
    startedAt: timestamp("started_at", { withTimezone: true }),
    finishedAt: timestamp("finished_at", { withTimezone: true }),
    createdAt: createdAt(),
  },
  (t) => [
    index("wazuh_sync_run_conn_idx").on(t.connectionId, t.createdAt, t.id),
    index("wazuh_sync_run_org_idx").on(t.organizationId, t.createdAt, t.id),
  ],
);

/**
 * "Summarise with AI" on the XDR page. The worker (the only process that opens the model's API
 * key) builds the prompt from the stored aggregates, calls the model and stores the answer here.
 * The content is an AI suggestion: untrusted text, rendered by the safe Markdown renderer.
 */
export const wazuhSummary = pgTable(
  "wazuh_summary",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    connectionId: text("connection_id")
      .notNull()
      .references(() => wazuhConnection.id, { onDelete: "cascade" }),
    status: text("status", { enum: ["pending", "running", "complete", "failed"] }).notNull(),
    language: text("language", { enum: ["en", "de"] })
      .notNull()
      .default("en"),
    content: text("content").notNull().default(""),
    /** A short code from packages/core/src/ai.ts (`AI_ERRORS`); null unless failed. */
    error: text("error"),
    model: text("model"),
    promptTokens: integer("prompt_tokens"),
    completionTokens: integer("completion_tokens"),
    latencyMs: integer("latency_ms"),
    requestedBy: text("requested_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
    finishedAt: timestamp("finished_at", { withTimezone: true }),
  },
  (t) => [index("wazuh_summary_conn_idx").on(t.connectionId, t.createdAt)],
);

/* -------------------------------------------------------------------------- */
/* Attack overview (ADR 0016): local GeoIP, retention, optional OSINT           */
/* -------------------------------------------------------------------------- */

const inet = customType<{ data: string }>({ dataType: () => "inet" });

/**
 * One load of a DB-IP CSV file (CC BY 4.0, never bundled): by an admin or by the opt-in monthly
 * download. A load runs in one transaction: its row is `loading` only inside that transaction, and
 * becomes `active` when the ranges have been validated and stored (the previous active dataset of
 * that kind is deleted in the same transaction, so a failed load changes nothing). `failed` rows
 * keep the reason of the last refused load per kind. Installation-wide public data, so there is no
 * organisation column.
 */
export const geoipDataset = pgTable(
  "geoip_dataset",
  {
    id: text("id").primaryKey(),
    kind: text("kind", { enum: ["country", "asn"] }).notNull(),
    state: text("state", { enum: ["loading", "active", "failed"] }).notNull(),
    source: text("source", { enum: ["import", "download"] }).notNull(),
    /** `YYYY-MM` of the DB-IP release (from the file name); null if the name did not say. */
    datasetMonth: text("dataset_month"),
    rowCount: integer("row_count"),
    /** SHA-256 (hex) of the compressed file as received. */
    sha256: text("sha256"),
    compressedBytes: bigint("compressed_bytes", { mode: "number" }),
    /** A code from packages/core/src/geoip.ts (`GeoipErrorCode`); null unless failed. */
    error: text("error"),
    importedBy: text("imported_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
    finishedAt: timestamp("finished_at", { withTimezone: true }),
  },
  (t) => [uniqueIndex("geoip_dataset_active_uq").on(t.kind).where(sql`${t.state} = 'active'`)],
);

/** Address ranges to country codes. Non-overlapping within a dataset, so one index lookup finds an address. */
export const geoipCountryRange = pgTable(
  "geoip_country_range",
  {
    datasetId: text("dataset_id")
      .notNull()
      .references(() => geoipDataset.id, { onDelete: "cascade" }),
    rangeStart: inet("range_start").notNull(),
    rangeEnd: inet("range_end").notNull(),
    country: text("country").notNull(),
  },
  (t) => [index("geoip_country_range_lookup").on(t.datasetId, t.rangeStart)],
);

/** Address ranges to autonomous system number and organisation. */
export const geoipAsnRange = pgTable(
  "geoip_asn_range",
  {
    datasetId: text("dataset_id")
      .notNull()
      .references(() => geoipDataset.id, { onDelete: "cascade" }),
    rangeStart: inet("range_start").notNull(),
    rangeEnd: inet("range_end").notNull(),
    asn: bigint("asn", { mode: "number" }).notNull(),
    org: text("org").notNull(),
  },
  (t) => [index("geoip_asn_range_lookup").on(t.datasetId, t.rangeStart)],
);

/**
 * Settings of the attack overview, one row per organisation: how long source addresses are kept,
 * the opt-in monthly GeoIP download and the optional OSINT enrichment. Everything that sends data
 * out is off by default. The OSINT API key lives in the vault (`secret`, purpose `osint-api-key`);
 * the API seals it, only the worker opens it.
 */
export const attackSettings = pgTable("attack_settings", {
  organizationId: text("organization_id")
    .primaryKey()
    .references(() => organization.id, { onDelete: "cascade" }),
  /** Stored source addresses and OSINT results older than this are deleted. */
  retentionDays: integer("retention_days").notNull().default(90),

  geoipDownloadEnabled: boolean("geoip_download_enabled").notNull().default(false),
  geoipDownloadEnabledBy: text("geoip_download_enabled_by").references(() => user.id, {
    onDelete: "set null",
  }),
  geoipDownloadEnabledAt: timestamp("geoip_download_enabled_at", { withTimezone: true }),
  geoipDownloadLastAttemptAt: timestamp("geoip_download_last_attempt_at", { withTimezone: true }),
  /** A code from packages/core/src/geoip.ts or "unreachable" / "notFound"; null if the last attempt worked or none was made. */
  geoipDownloadLastError: text("geoip_download_last_error"),

  osintEnabled: boolean("osint_enabled").notNull().default(false),
  osintProvider: text("osint_provider", { enum: ["abuseipdb"] }),
  osintSecretId: text("osint_secret_id").references(() => secret.id, { onDelete: "set null" }),
  /** At most this many addresses are looked up per sync, busiest first. */
  osintTopN: integer("osint_top_n").notNull().default(20),
  osintDailyBudget: integer("osint_daily_budget").notNull().default(300),
  /** Who confirmed that addresses leave the network and that the provider's terms were checked, and when. */
  osintAcknowledgedBy: text("osint_acknowledged_by").references(() => user.id, { onDelete: "set null" }),
  osintAcknowledgedAt: timestamp("osint_acknowledged_at", { withTimezone: true }),
  /** Requests made on `osintUsageDay` (a UTC date), for the daily budget. */
  osintUsageDay: date("osint_usage_day"),
  osintUsageCount: integer("osint_usage_count").notNull().default(0),
  osintLastRunAt: timestamp("osint_last_run_at", { withTimezone: true }),
  /** A code from packages/core/src/osint.ts (`OsintErrorCode`); null if the last run worked. */
  osintLastError: text("osint_last_error"),

  updatedAt: updatedAt(),
});

/** What a provider said about a public source address, kept for 24 hours and then looked up again; score, count and date only. */
export const attackOsintResult = pgTable(
  "attack_osint_result",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    provider: text("provider", { enum: ["abuseipdb"] }).notNull(),
    /** Canonical text of the address (packages/core/src/geoip.ts `canonicalIp`). */
    ip: text("ip").notNull(),
    score: integer("score").notNull(),
    reports: integer("reports").notNull(),
    lastReportedAt: timestamp("last_reported_at", { withTimezone: true }),
    checkedAt: timestamp("checked_at", { withTimezone: true }).notNull(),
  },
  (t) => [
    uniqueIndex("attack_osint_result_uq").on(t.organizationId, t.provider, t.ip),
    index("attack_osint_result_checked_idx").on(t.checkedAt),
  ],
);

/**
 * "Summarise with AI" on the Attacks page. Same life cycle as `wazuh_summary`; the model sees
 * numbers per country and AS only, never an address (packages/core/src/attack-summary.ts).
 */
export const attackSummary = pgTable(
  "attack_summary",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    connectionId: text("connection_id")
      .notNull()
      .references(() => wazuhConnection.id, { onDelete: "cascade" }),
    status: text("status", { enum: ["pending", "running", "complete", "failed"] }).notNull(),
    language: text("language", { enum: ["en", "de"] })
      .notNull()
      .default("en"),
    content: text("content").notNull().default(""),
    error: text("error"),
    model: text("model"),
    promptTokens: integer("prompt_tokens"),
    completionTokens: integer("completion_tokens"),
    latencyMs: integer("latency_ms"),
    requestedBy: text("requested_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
    finishedAt: timestamp("finished_at", { withTimezone: true }),
  },
  (t) => [index("attack_summary_conn_idx").on(t.connectionId, t.createdAt)],
);

/* -------------------------------------------------------------------------- */
/* AI triage                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * The organisation's model endpoint (ADR 0013). The API key is sealed in `secret` (purpose
 * "ai-api-key"): the API seals it, only the worker opens it, so only the worker calls the model.
 */
export const aiSettings = pgTable("ai_settings", {
  organizationId: text("organization_id")
    .primaryKey()
    .references(() => organization.id, { onDelete: "cascade" }),
  /** OpenAI-compatible base URL, e.g. https://llm.example.lan/v1 (no trailing slash). */
  baseUrl: text("base_url").notNull(),
  model: text("model").notNull(),
  apiKeySecretId: text("api_key_secret_id").references(() => secret.id, { onDelete: "set null" }),
  /**
   * How much code context the model may see: "excerpt" or "metadata". Only "metadata" is
   * implemented (GarnetOps keeps no clones); "excerpt" is reserved for a later version.
   */
  contextPolicy: text("context_policy", { enum: ["excerpt", "metadata"] })
    .notNull()
    .default("excerpt"),
  /** Off until an admin switches it on; a stored configuration alone never sends anything. */
  enabled: boolean("enabled").notNull().default(false),
  maxTokens: integer("max_tokens").notNull().default(1024),
  temperature: real("temperature").notNull().default(0.2),
  /** Wall-clock limit of one generation. */
  timeoutSeconds: integer("timeout_seconds").notNull().default(120),
  /** Generations that may run at the same time for the organisation. */
  maxConcurrent: integer("max_concurrent").notNull().default(2),
  /**
   * Where the endpoint sits when it was last resolved: "private" (RFC 1918, ULA, shared
   * address space), "external" (any public address) or "unknown". Findings leave the network
   * for "external" only, and only after `externalAckHost` matches the host.
   */
  endpointScope: text("endpoint_scope", { enum: ["private", "external", "unknown"] })
    .notNull()
    .default("unknown"),
  /** The host an admin confirmed finding data may be sent to although it is outside the network. */
  externalAckHost: text("external_ack_host"),
  externalAckBy: text("external_ack_by").references(() => user.id, { onDelete: "set null" }),
  externalAckAt: timestamp("external_ack_at", { withTimezone: true }),
  updatedBy: text("updated_by").references(() => user.id, { onDelete: "set null" }),
  updatedAt: updatedAt(),
});

/**
 * "Load models" and "Test connection": the API cannot open the API key, so it queues a probe
 * and the worker writes the result here. Short-lived; the worker sweeps old rows.
 */
export const aiProbe = pgTable(
  "ai_probe",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    kind: text("kind", { enum: ["models", "test"] }).notNull(),
    baseUrl: text("base_url").notNull(),
    model: text("model"),
    /** A key sealed for this probe (typed in the form) or the stored one. */
    secretId: text("secret_id").references(() => secret.id, { onDelete: "set null" }),
    /** True when `secretId` was made for this probe only; the worker deletes it afterwards. */
    tempSecret: boolean("temp_secret").notNull().default(false),
    /** The host the admin acknowledged for an external endpoint (checked by the worker). */
    ackHost: text("ack_host"),
    status: text("status", { enum: ["pending", "done"] })
      .notNull()
      .default("pending"),
    /** { ok, error?, models?, latencyMs?, replyChars?, scope? }; never model output or response bodies. */
    result: jsonb("result").$type<Record<string, unknown>>(),
    requestedBy: text("requested_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
  },
  (t) => [index("ai_probe_org_idx").on(t.organizationId, t.createdAt)],
);

/** One conversation per finding, shared within the organisation; every message records its author. */
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
  (t) => [
    index("chat_thread_finding_idx").on(t.findingId, t.createdAt),
    uniqueIndex("chat_thread_finding_uq").on(t.findingId),
  ],
);

export const chatMessage = pgTable(
  "chat_message",
  {
    id: text("id").primaryKey(),
    threadId: text("thread_id")
      .notNull()
      .references(() => chatThread.id, { onDelete: "cascade" }),
    /** Order inside the thread, independent of clocks. */
    seq: bigserial("seq", { mode: "number" }).notNull(),
    role: text("role", { enum: ["user", "assistant"] }).notNull(),
    /** "triage": the structured first answer; "chat": a question or a free-text answer. */
    kind: text("kind", { enum: ["triage", "chat"] })
      .notNull()
      .default("chat"),
    /** Raw text. For a triage answer the model's JSON; it is parsed into `structured`, never executed. */
    content: text("content").notNull(),
    /** "pending": queued for the worker; "streaming": being written; the rest are final. */
    status: text("status", { enum: ["pending", "complete", "streaming", "stopped", "failed"] }).notNull(),
    /** The validated triage result of a triage answer, or null (then `content` is shown as text). */
    structured: jsonb("structured").$type<Record<string, unknown>>(),
    /** A short, safe code of why a generation failed (never a response body or a secret). */
    error: text("error"),
    model: text("model"),
    promptTokens: integer("prompt_tokens"),
    completionTokens: integer("completion_tokens"),
    latencyMs: integer("latency_ms"),
    /** The context the model received, so users can see exactly what it saw. */
    context: jsonb("context"),
    createdBy: text("created_by").references(() => user.id, { onDelete: "set null" }),
    createdAt: createdAt(),
  },
  (t) => [
    index("chat_message_thread_idx").on(t.threadId, t.createdAt, t.id),
    index("chat_message_thread_seq_idx").on(t.threadId, t.seq),
    index("chat_message_active_idx").on(t.status, t.createdAt),
  ],
);

/**
 * A note on a finding. Today only created by a human accepting an AI suggestion; the author
 * is that human, `source` says where the text came from.
 */
export const findingNote = pgTable(
  "finding_note",
  {
    id: text("id").primaryKey(),
    organizationId: text("organization_id")
      .notNull()
      .references(() => organization.id, { onDelete: "cascade" }),
    findingId: text("finding_id")
      .notNull()
      .references(() => finding.id, { onDelete: "cascade" }),
    authorUserId: text("author_user_id").references(() => user.id, { onDelete: "set null" }),
    body: text("body").notNull(),
    source: text("source", { enum: ["manual", "ai"] })
      .notNull()
      .default("manual"),
    /** The AI message the note was taken from; one note per message. */
    messageId: text("message_id").references(() => chatMessage.id, { onDelete: "set null" }),
    /** For AI notes: { exploitability, reachable, confidence, upgradeTo }. */
    meta: jsonb("meta").$type<Record<string, unknown>>(),
    createdAt: createdAt(),
  },
  (t) => [
    index("finding_note_finding_idx").on(t.findingId, t.createdAt),
    uniqueIndex("finding_note_message_uq").on(t.messageId),
  ],
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
