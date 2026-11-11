/**
 * Files a website must not serve publicly (ADR 0050). Pure: the paths that are asked for, the kind of file each one is, its fixed
 * severity, and the content signature that proves it. A file counts only when its first bytes prove it, so a site that answers
 * every path with its own page ("soft 404") is not reported. Nothing of a body is ever kept: only whether it matched.
 */

export const EXPOSED_FILE_KINDS = [
  "envFile",
  "gitRepository",
  "cloudCredentials",
  "registryToken",
  "htpasswd",
  "aiAgentSettings",
  "configBackup",
  "sqlDump",
  "archive",
  "phpinfo",
  "serverStatus",
  "dsStore",
] as const;
export type ExposedFileKind = (typeof EXPOSED_FILE_KINDS)[number];

export const EXPOSED_FILE_SEVERITY: Record<ExposedFileKind, "critical" | "high" | "medium" | "low"> = {
  envFile: "critical",
  cloudCredentials: "critical",
  registryToken: "critical",
  configBackup: "critical",
  gitRepository: "high",
  sqlDump: "high",
  archive: "high",
  htpasswd: "high",
  aiAgentSettings: "high",
  phpinfo: "medium",
  serverStatus: "medium",
  dsStore: "low",
};

/** The paths, in the order they are asked for. At most 24 (ADR 0050). */
export const EXPOSED_FILE_PROBES: readonly { path: string; kind: ExposedFileKind }[] = [
  { path: "/.env", kind: "envFile" },
  { path: "/.env.production", kind: "envFile" },
  { path: "/.env.local", kind: "envFile" },
  { path: "/.git/HEAD", kind: "gitRepository" },
  { path: "/.git/config", kind: "gitRepository" },
  { path: "/.aws/credentials", kind: "cloudCredentials" },
  { path: "/.npmrc", kind: "registryToken" },
  { path: "/.htpasswd", kind: "htpasswd" },
  { path: "/.claude/settings.local.json", kind: "aiAgentSettings" },
  { path: "/wp-config.php.bak", kind: "configBackup" },
  { path: "/wp-config.php~", kind: "configBackup" },
  { path: "/wp-config.php.save", kind: "configBackup" },
  { path: "/wp-config.old", kind: "configBackup" },
  { path: "/config.php.bak", kind: "configBackup" },
  { path: "/backup.sql", kind: "sqlDump" },
  { path: "/dump.sql", kind: "sqlDump" },
  { path: "/database.sql", kind: "sqlDump" },
  { path: "/db.sql", kind: "sqlDump" },
  { path: "/backup.zip", kind: "archive" },
  { path: "/backup.tar.gz", kind: "archive" },
  { path: "/phpinfo.php", kind: "phpinfo" },
  { path: "/info.php", kind: "phpinfo" },
  { path: "/server-status", kind: "serverStatus" },
  { path: "/.DS_Store", kind: "dsStore" },
];

export const EXPOSED_FILES_LIMITS = {
  /** Bytes of a body that are read before the connection is closed. */
  maxBody: 8 * 1024,
  timeoutMs: 8_000,
  /** Pause between two requests to the same site. */
  gapMs: 250,
} as const;

const startsWith = (body: Uint8Array, bytes: readonly number[]) =>
  body.length >= bytes.length && bytes.every((b, i) => body[i] === b);

/** A page the site renders, which no file of a non-HTML kind ever is. */
const looksLikeHtml = (text: string) => /^\s*(?:<!doctype html|<html|<head|<body|<\?xml)/i.test(text);

const SIGNATURES: Record<ExposedFileKind, (body: Uint8Array, text: string) => boolean> = {
  // At least two assignments with a value, the way .env files look.
  envFile: (_, text) => (text.match(/^\s*(?:export\s+)?[A-Z][A-Z0-9_]{1,63}\s*=\s*\S+/gm) ?? []).length >= 2,
  gitRepository: (_, text) => /^ref: refs\/[\w./-]+\s*$/m.test(text) || /^\[core\]\s*$/m.test(text),
  cloudCredentials: (_, text) => /^\s*aws_(?:access_key_id|secret_access_key)\s*=\s*\S+/m.test(text),
  registryToken: (_, text) => /_(?:authToken|auth|password)\s*=\s*\S{6,}/.test(text),
  htpasswd: (_, text) => /^[^:\s]{1,64}:(?:\$apr1\$|\$2[aby]\$|\{SHA\}|\$[56]\$)/m.test(text),
  aiAgentSettings: (_, text) => /"permissions"\s*:/.test(text) && /"(?:allow|deny)"\s*:/.test(text),
  configBackup: (_, text) =>
    /define\(\s*['"]DB_PASSWORD['"]/.test(text) || /\$(?:db_?)?pass(?:word)?\s*=\s*['"]/i.test(text),
  sqlDump: (_, text) =>
    /^-- (?:MySQL|MariaDB|PostgreSQL) (?:dump|database dump)/m.test(text) ||
    /^\s*(?:CREATE TABLE|INSERT INTO)\s/im.test(text),
  // ZIP local file header, or gzip.
  archive: (body) => startsWith(body, [0x50, 0x4b, 0x03, 0x04]) || startsWith(body, [0x1f, 0x8b]),
  phpinfo: (_, text) => /<title>\s*(?:PHP \d[^<]*- )?phpinfo\(\)\s*<\/title>/i.test(text),
  serverStatus: (_, text) =>
    /<title>\s*Apache Status\s*<\/title>/i.test(text) || /<h1>\s*Apache Server Status for/i.test(text),
  // .DS_Store: a 4-byte header 0x00000001 and the "Bud1" magic.
  dsStore: (body) => startsWith(body, [0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31]),
};

/** Kinds whose real content is HTML; every other kind never is. */
const HTML_KINDS = new Set<ExposedFileKind>(["phpinfo", "serverStatus"]);

/** Whether an answer proves the file is served: status 200 and the signature of its kind in the first bytes. */
export function provesExposedFile(kind: ExposedFileKind, status: number | null, body: Uint8Array): boolean {
  if (status !== 200 || body.length === 0) return false;
  const text = new TextDecoder("utf-8", { fatal: false }).decode(
    body.subarray(0, EXPOSED_FILES_LIMITS.maxBody),
  );
  if (!HTML_KINDS.has(kind) && looksLikeHtml(text)) return false;
  return SIGNATURES[kind](body, text);
}

/** What a run found: the paths that proved to be served, and how many requests got no answer to judge. */
export interface ExposedFilesSnapshot {
  /** Why nothing was asked: the name's control is not proved (any more), or HTTPS did not answer. */
  error: "notVerified" | "noHttps" | null;
  checked: number;
  failed: number;
  found: { path: string; kind: ExposedFileKind }[];
}
