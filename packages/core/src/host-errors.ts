/**
 * Messages the worker stores when a server's host key scan or inventory fails (ADR 0011).
 * Same pattern as scan-errors.ts: the worker writes the English text, the web app maps it
 * back to its code and shows it in the user's language; unknown texts are shown as they are.
 * Never contains output of the server, an address or a secret.
 *
 * Changing a text here changes what older rows map to: add a new code instead.
 */
export const HOST_ERRORS = {
  hostRemoved: "The server was removed.",
  hostKeyNotConfirmed: "The host key is not confirmed yet. Confirm its fingerprint first.",
  accessKeyMissing: "The access key of this installation is not ready yet.",
  sshClientMissing: "No ssh client found. Install OpenSSH on the worker.",
  addressRefused: "The address points to a loopback, link-local or otherwise reserved address.",
  addressUnresolvable: "The address could not be resolved.",
  hostUnreachable: "The server could not be reached.",
  keyscanFailed: "No SSH host key could be read from the server. Check the address and port.",
  noKeyExchange: "The server offers no secure SSH key exchange that GarnetOps accepts.",
  keyscanWeakKey: "The server offers only SSH host keys that are too weak to pin.",
  hostKeyChanged:
    "The server's host key changed. An admin must confirm the new fingerprint before the inventory runs again.",
  accessRefused:
    "The server refused the access key. Run the host setup script again and check the allowed source address.",
  commandRefused:
    "The server did not run the inventory command. Run the host setup script again to update the wrapper.",
  inventoryTimeout: "The inventory took longer than {seconds} seconds.",
  inventoryTooLarge: "The inventory is larger than the {limit} MB limit.",
  inventoryInvalid: "The server returned an inventory in an unexpected format.",
  osUnknown: "The operating system is not recognised, so vulnerabilities cannot be matched.",
  scannerFailed: "The vulnerability scanner failed. Check that the vulnerability database is installed.",
  unexpected: "The inventory failed unexpectedly. The worker log has details.",
} as const;

export type HostErrorCode = keyof typeof HOST_ERRORS;
export type HostErrorParams = Record<string, string | number>;

/** The stored English text of a host error, with its parameters filled in. */
export function hostErrorMessage(code: HostErrorCode, params: HostErrorParams = {}): string {
  return HOST_ERRORS[code].replace(/\{(\w+)\}/g, (match, name: string) =>
    name in params ? String(params[name]) : match,
  );
}

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const PATTERNS = (Object.entries(HOST_ERRORS) as [HostErrorCode, string][]).map(([code, text]) => {
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

/** The code and parameters of a stored host error text, or null for a text this version does not know. */
export function parseHostError(message: string): { code: HostErrorCode; params: HostErrorParams } | null {
  for (const { code, names, pattern } of PATTERNS) {
    const match = pattern.exec(message);
    if (match) return { code, params: Object.fromEntries(names.map((n, i) => [n, match[i + 1] ?? ""])) };
  }
  return null;
}

/** An error whose message is one of the texts above: safe to store and show. */
export class HostError extends Error {
  readonly code: HostErrorCode;
  constructor(code: HostErrorCode, params: HostErrorParams = {}) {
    super(hostErrorMessage(code, params));
    this.code = code;
  }
}
