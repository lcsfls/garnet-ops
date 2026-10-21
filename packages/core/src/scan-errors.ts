/**
 * Messages the worker stores when a scan fails. The worker writes the English
 * text (it is also what the API returns), and the web app maps it back to its
 * code to show it in the user's language. Rows written by earlier versions
 * carry the same texts, so they are translated too; unknown texts are shown
 * as they are.
 *
 * Changing a text here changes what older rows map to: add a new code instead.
 */
export const SCAN_ERRORS = {
  repositoryRemoved: "The repository was removed.",
  deployKeyMissing: "The deploy key is missing. Reconnect the repository.",
  credentialMissing: "The stored credential is missing. Reconnect the repository.",
  sshClientMissing: "No ssh client found. Install OpenSSH on the worker.",
  sshNoKeyExchange: "The ssh client supports none of the allowed key exchanges.",
  hostKeyMismatch:
    "The server's SSH host key does not match the pinned key. If the server was reinstalled, an admin can clear the pinned key; otherwise someone may be intercepting the connection.",
  deployKeyRefused:
    "The server refused the deploy key. Add the public key to the repository as a read-only deploy key.",
  serverNoKeyExchange: "The server offers no secure SSH key exchange that GarnetOps accepts.",
  branchNotFound: "The branch does not exist.",
  accessRefused: "The repository refused access. Check the token and its read permission.",
  repositoryNotFound: "The repository was not found. Check the URL and that the token can see it.",
  hostUnreachable: "The repository host could not be reached.",
  cloneFailed: "Cloning the repository failed.",
  repositoryTooLarge: "The repository is larger than the {limit} MB limit.",
  sbomFailed: "Building the package inventory (SBOM) failed.",
  scannerFailed: "The vulnerability scanner failed. Check that the vulnerability database is installed.",
  unexpected: "The scan failed unexpectedly. The worker log has details.",
  refNotFound: "The requested ref does not exist in the repository.",
  commitMismatch: "The ref points to a different commit than the gate check expected.",
} as const;

export type ScanErrorCode = keyof typeof SCAN_ERRORS;
export type ScanErrorParams = Record<string, string | number>;

/** The stored English text of a scan error, with its parameters filled in. */
export function scanErrorMessage(code: ScanErrorCode, params: ScanErrorParams = {}): string {
  return SCAN_ERRORS[code].replace(/\{(\w+)\}/g, (match, name: string) =>
    name in params ? String(params[name]) : match,
  );
}

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

const PATTERNS = (Object.entries(SCAN_ERRORS) as [ScanErrorCode, string][]).map(([code, text]) => {
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

/** The code and parameters of a stored scan error text, or null for a text this version does not know. */
export function parseScanError(message: string): { code: ScanErrorCode; params: ScanErrorParams } | null {
  for (const { code, names, pattern } of PATTERNS) {
    const match = pattern.exec(message);
    if (match) return { code, params: Object.fromEntries(names.map((n, i) => [n, match[i + 1] ?? ""])) };
  }
  return null;
}
