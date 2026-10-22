/**
 * Messages the worker stores when a UniFi certificate check, sync or IPS poll fails (ADR 0022).
 * Same pattern as proxmox-errors.ts: the worker writes the English text, the web app maps it back
 * to its code and shows it in the user's language; unknown texts are shown as they are.
 * Never contains output of the console, an address, a key, a password or a certificate.
 *
 * Changing a text here changes what older rows map to: add a new code instead.
 */
export const UNIFI_ERRORS = {
  connectionRemoved: "The UniFi connection was removed.",
  certificateNotConfirmed: "The certificate is not confirmed yet. Confirm its fingerprint first.",
  certificateChanged:
    "The certificate of the UniFi console changed. An admin must confirm the new fingerprint before the next sync.",
  keyMissing: "The API key is not available. Edit the connection and enter the key again.",
  addressRefused: "The address points to a loopback, link-local or otherwise reserved address.",
  addressUnresolvable: "The address could not be resolved.",
  unreachable: "The UniFi console could not be reached.",
  timeout: "The UniFi console did not answer in time.",
  tlsFailed: "The TLS connection to the UniFi console failed.",
  keyRejected: "The console rejected the API key. Create a new key and enter it again.",
  forbidden: "The API key may not read this information.",
  notUnifi:
    "The console did not answer like the UniFi Network API. Check the address and the API path (UniFi OS console or self-hosted application).",
  rateLimited: "The console is limiting requests. GarnetOps tries again later.",
  invalidResponse: "The console returned an answer in an unexpected format.",
  responseTooLarge: "A console answer is larger than the {limit} MB limit.",
  redirected: "The console redirected the request. Redirects are not followed.",
  serverError: "The console reported an error. Check the console.",
  tooManyRequests: "The sync was stopped because it would send too many requests.",
  syncTimeout: "The sync took longer than {minutes} minutes and was stopped.",
  ipsCredentialsMissing: "The password of the IPS user is not available. Enter it again.",
  ipsLoginRejected:
    "The console rejected the login of the IPS user. Check the user name and password; the user must be a local user without two-factor sign-in.",
  ipsSessionRejected: "The console did not accept the session of the IPS user.",
  ipsEndpointMissing:
    "This console does not offer the threat event endpoint GarnetOps expects. The preview does not work with this version.",
  unexpected: "The sync failed unexpectedly. The worker log has details.",
} as const;

export type UnifiErrorCode = keyof typeof UNIFI_ERRORS;
export type UnifiErrorParams = Record<string, string | number>;

/** The stored English text of a UniFi error, with its parameters filled in. */
export function unifiErrorMessage(code: UnifiErrorCode, params: UnifiErrorParams = {}): string {
  return UNIFI_ERRORS[code].replace(/\{(\w+)\}/g, (match, name: string) =>
    name in params ? String(params[name]) : match,
  );
}

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const PATTERNS = (Object.entries(UNIFI_ERRORS) as [UnifiErrorCode, string][]).map(([code, text]) => {
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

/** The code and parameters of a stored UniFi error text, or null for a text this version does not know. */
export function parseUnifiError(message: string): { code: UnifiErrorCode; params: UnifiErrorParams } | null {
  for (const { code, names, pattern } of PATTERNS) {
    const match = pattern.exec(message);
    if (match) return { code, params: Object.fromEntries(names.map((n, i) => [n, match[i + 1] ?? ""])) };
  }
  return null;
}

/** An error whose message is one of the texts above: safe to store and show. */
export class UnifiError extends Error {
  readonly code: UnifiErrorCode;
  /** HTTP status of the console's answer, if there was one. */
  readonly status: number | undefined;
  constructor(code: UnifiErrorCode, params: UnifiErrorParams = {}, status?: number) {
    super(unifiErrorMessage(code, params));
    this.code = code;
    this.status = status;
  }
}

/**
 * Things a sync could not read but carried on without (an endpoint may be missing in this version of the
 * Network application). Stored as codes on the run and translated by the web.
 */
export const UNIFI_WARNINGS = [
  "statisticsUnreadable",
  "clientsUnreadable",
  "siteUnreadable",
  "sitesTruncated",
  "devicesTruncated",
  "entriesDropped",
] as const;
export type UnifiWarning = (typeof UNIFI_WARNINGS)[number];
