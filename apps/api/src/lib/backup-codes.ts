import { generateRandomString, symmetricDecrypt, symmetricEncrypt } from "better-auth/crypto";

/**
 * Backup codes in the format better-auth's two-factor plugin reads when someone signs in with
 * one: a JSON list of "xxxxx-xxxxx" strings, encrypted with the auth secret. (The plugin's own
 * helpers are not exported at run time, so the account page makes them here.)
 */
export const BACKUP_CODE_COUNT = 10;

/** Ten fresh codes, each 10 random letters and digits written as two groups of five. */
export function newBackupCodes(): string[] {
  return Array.from({ length: BACKUP_CODE_COUNT }, () => {
    const code = generateRandomString(10, "a-z", "0-9", "A-Z");
    return `${code.slice(0, 5)}-${code.slice(5)}`;
  });
}

export async function sealBackupCodes(codes: string[], key: Parameters<typeof symmetricEncrypt>[0]["key"]) {
  return symmetricEncrypt({ key, data: JSON.stringify(codes) });
}

/** The unused codes in a stored value, or null when it cannot be read. */
export async function openBackupCodes(
  sealed: string,
  key: Parameters<typeof symmetricDecrypt>[0]["key"],
): Promise<string[] | null> {
  try {
    const parsed: unknown = JSON.parse(await symmetricDecrypt({ key, data: sealed }));
    return Array.isArray(parsed) && parsed.every((c) => typeof c === "string") ? parsed : null;
  } catch {
    return null;
  }
}
