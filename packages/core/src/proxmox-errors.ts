/**
 * Messages the worker stores when a Proxmox VE certificate check or sync fails (ADR 0012).
 * Same pattern as host-errors.ts: the worker writes the English text, the web app maps it back
 * to its code and shows it in the user's language; unknown texts are shown as they are.
 * Never contains output of the Proxmox API, an address, a token or a certificate.
 *
 * Changing a text here changes what older rows map to: add a new code instead.
 */
export const PROXMOX_ERRORS = {
  clusterRemoved: "The Proxmox connection was removed.",
  certificateNotConfirmed: "The certificate is not confirmed yet. Confirm its fingerprint first.",
  certificateChanged:
    "The certificate of the Proxmox server changed. An admin must confirm the new fingerprint before the next sync.",
  tokenMissing: "The API token secret is not available. Edit the connection and enter the token again.",
  addressRefused: "The address points to a loopback, link-local or otherwise reserved address.",
  addressUnresolvable: "The address could not be resolved.",
  unreachable: "The Proxmox server could not be reached.",
  timeout: "The Proxmox server did not answer in time.",
  tlsFailed: "The TLS connection to the Proxmox server failed.",
  tokenRejected: "Proxmox rejected the API token. Check the token ID and secret.",
  forbidden:
    "The token may not read the inventory. Give the user and the token the role PVEAuditor on the path / .",
  notProxmox: "The server did not answer like Proxmox VE.",
  invalidResponse: "Proxmox returned an answer in an unexpected format.",
  responseTooLarge: "A Proxmox answer is larger than the {limit} MB limit.",
  redirected: "Proxmox redirected the request. Redirects are not followed.",
  serverError: "Proxmox reported an error. Check the server.",
  permissionsUnreadable: "The permissions of the token could not be read.",
  privilegesNotAcknowledged:
    "The token can do more than read. An admin must acknowledge this before anything is synced.",
  tooManyRequests: "The sync was stopped because it would send too many requests.",
  syncTimeout: "The sync took longer than {minutes} minutes and was stopped.",
  unexpected: "The sync failed unexpectedly. The worker log has details.",
} as const;

export type ProxmoxErrorCode = keyof typeof PROXMOX_ERRORS;
export type ProxmoxErrorParams = Record<string, string | number>;

/** The stored English text of a Proxmox error, with its parameters filled in. */
export function proxmoxErrorMessage(code: ProxmoxErrorCode, params: ProxmoxErrorParams = {}): string {
  return PROXMOX_ERRORS[code].replace(/\{(\w+)\}/g, (match, name: string) =>
    name in params ? String(params[name]) : match,
  );
}

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const PATTERNS = (Object.entries(PROXMOX_ERRORS) as [ProxmoxErrorCode, string][]).map(([code, text]) => {
  const names: string[] = [];
  const source = text
    .split(/(\{\w+\})/)
    .map((part) => {
      const name = /^\{(\w+)\}$/.exec(part)?.[1];
      if (!name) return escapeRegExp(part);
      names.push(name);
      return "(.+?)";
    })
    .join("");
  return { code, names, pattern: new RegExp(`^${source}$`) };
});

/** The code and parameters of a stored Proxmox error text, or null for a text this version does not know. */
export function parseProxmoxError(
  message: string,
): { code: ProxmoxErrorCode; params: ProxmoxErrorParams } | null {
  for (const { code, names, pattern } of PATTERNS) {
    const match = pattern.exec(message);
    if (match) return { code, params: Object.fromEntries(names.map((n, i) => [n, match[i + 1] ?? ""])) };
  }
  return null;
}

/** An error whose message is one of the texts above: safe to store and show. */
export class ProxmoxError extends Error {
  readonly code: ProxmoxErrorCode;
  /** HTTP status of the Proxmox answer, if there was one. */
  readonly status: number | undefined;
  constructor(code: ProxmoxErrorCode, params: ProxmoxErrorParams = {}, status?: number) {
    super(proxmoxErrorMessage(code, params));
    this.code = code;
    this.status = status;
  }
}

/**
 * Things a sync could not read but carried on without (the token may lack a privilege, an
 * endpoint may not exist in this version). Stored as codes on the run and translated by the web.
 */
export const PROXMOX_WARNINGS = [
  "backupsUnreadable",
  "backupJobsUnreadable",
  "updatesUnreadable",
  "haUnreadable",
  "detailsUnreadable",
  "nodeOffline",
  "addressesUnreadable",
  "guestsTruncated",
  "entriesDropped",
] as const;
export type ProxmoxWarning = (typeof PROXMOX_WARNINGS)[number];
