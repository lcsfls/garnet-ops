/**
 * Messages the worker stores when a Wazuh certificate check or sync fails (ADR 0015). Same
 * pattern as proxmox-errors.ts: the worker writes the English text, the web app maps it back to
 * its code and shows it in the user's language; unknown texts are shown as they are. Never
 * contains output of Wazuh, an address, a user name, a password, a token or a certificate.
 *
 * `{endpoint}` is "manager API" or "indexer" (the English words below); the web app maps the
 * parameter back to a translated name. Changing a text here changes what older rows map to: add a
 * new code instead.
 */
export const WAZUH_ENDPOINT_NAMES = { manager: "manager API", indexer: "indexer" } as const;
export type WazuhEndpointKind = keyof typeof WAZUH_ENDPOINT_NAMES;

export const WAZUH_ERRORS = {
  connectionRemoved: "The Wazuh connection was removed.",
  certificateNotConfirmed:
    "The certificate of the Wazuh {endpoint} is not confirmed yet. Confirm its fingerprint first.",
  certificateChanged:
    "The certificate of the Wazuh {endpoint} changed. An admin must confirm the new fingerprint before the next sync.",
  credentialsMissing:
    "The password for the Wazuh {endpoint} is not available. Edit the connection and enter it again.",
  addressRefused: "The address of the Wazuh {endpoint} points to a loopback, link-local or reserved address.",
  addressUnresolvable: "The address of the Wazuh {endpoint} could not be resolved.",
  unreachable: "The Wazuh {endpoint} could not be reached.",
  timeout: "The Wazuh {endpoint} did not answer in time.",
  tlsFailed: "The TLS connection to the Wazuh {endpoint} failed.",
  caRejected:
    "The certificate of the Wazuh {endpoint} is not signed by the certificate authority you uploaded, or does not match its address.",
  loginRejected: "The Wazuh {endpoint} rejected the user name or password.",
  forbidden: "The user of the Wazuh {endpoint} may not read what GarnetOps needs. Check its role.",
  notWazuh: "The server did not answer like the Wazuh {endpoint}.",
  unsupportedVersion: "Wazuh {version} is not supported. GarnetOps reads Wazuh 4.x and 5.x.",
  invalidResponse: "The Wazuh {endpoint} returned an answer in an unexpected format.",
  responseTooLarge: "An answer of the Wazuh {endpoint} is larger than the {limit} MB limit.",
  redirected: "The Wazuh {endpoint} redirected the request. Redirects are not followed.",
  rateLimited: "The Wazuh {endpoint} is limiting requests. The next sync tries again.",
  serverError: "The Wazuh {endpoint} reported an error. Check the server.",
  policiesUnreadable: "The permissions of the Wazuh API user could not be read.",
  privilegesNotAcknowledged:
    "The Wazuh users can do more than read. An admin must acknowledge this before anything is synced.",
  tooManyRequests: "The sync was stopped because it would send too many requests.",
  syncTimeout: "The sync took longer than {minutes} minutes and was stopped.",
  unexpected: "The sync failed unexpectedly. The worker log has details.",
} as const;

export type WazuhErrorCode = keyof typeof WAZUH_ERRORS;
export type WazuhErrorParams = Record<string, string | number>;

/** The stored English text of a Wazuh error, with its parameters filled in. */
export function wazuhErrorMessage(code: WazuhErrorCode, params: WazuhErrorParams = {}): string {
  return WAZUH_ERRORS[code].replace(/\{(\w+)\}/g, (match, name: string) =>
    name in params ? String(params[name]) : match,
  );
}

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const PATTERNS = (Object.entries(WAZUH_ERRORS) as [WazuhErrorCode, string][]).map(([code, text]) => {
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

/** The code and parameters of a stored Wazuh error text, or null for a text this version does not know. */
export function parseWazuhError(message: string): { code: WazuhErrorCode; params: WazuhErrorParams } | null {
  for (const { code, names, pattern } of PATTERNS) {
    const match = pattern.exec(message);
    if (match) return { code, params: Object.fromEntries(names.map((n, i) => [n, match[i + 1] ?? ""])) };
  }
  return null;
}

/** An error whose message is one of the texts above: safe to store and show. */
export class WazuhError extends Error {
  readonly code: WazuhErrorCode;
  /** HTTP status of the Wazuh answer, if there was one. */
  readonly status: number | undefined;
  /** Which of the two endpoints raised it, when that is known. */
  readonly endpoint: WazuhEndpointKind | undefined;
  constructor(
    code: WazuhErrorCode,
    params: WazuhErrorParams & { endpoint?: WazuhEndpointKind } = {},
    status?: number,
  ) {
    const { endpoint, ...rest } = params;
    super(
      wazuhErrorMessage(code, {
        ...rest,
        ...(endpoint ? { endpoint: WAZUH_ENDPOINT_NAMES[endpoint] } : {}),
      }),
    );
    this.code = code;
    this.status = status;
    this.endpoint = endpoint;
  }

  /** The same error, attributed to an endpoint (the HTTP layer does not know which one it serves). */
  forEndpoint(endpoint: WazuhEndpointKind): WazuhError {
    return new WazuhError(this.code, { ...this.params, endpoint }, this.status);
  }

  /** Parameters other than the endpoint, kept so an error can be re-raised for an endpoint. */
  get params(): WazuhErrorParams {
    return parseWazuhError(this.message)?.params ?? {};
  }
}

/**
 * Things a sync could not read but carried on without (a role may lack an index, an endpoint may
 * not exist in this version). Stored as codes on the run and translated by the web app.
 */
export const WAZUH_WARNINGS = [
  "alertsUnreadable",
  "vulnerabilitiesUnreadable",
  "fimUnreadable",
  "rolesUnreadable",
  "agentsTruncated",
  "entriesDropped",
] as const;
export type WazuhWarning = (typeof WAZUH_WARNINGS)[number];
