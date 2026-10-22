import type { PasskeyOptions } from "@better-auth/passkey";
import { APIError } from "better-auth";

/**
 * Passkey rules that better-auth's plugin does not enforce itself (ADR 0017).
 *
 * The plugin verifies signatures, origin and RP ID, but it calls the WebAuthn verification with
 * `requireUserVerification: false` and asks for user verification only as "preferred" when it
 * signs someone in. A passkey counts as a second factor (and replaces password and code) only
 * because the authenticator checked the person (PIN, fingerprint, face), so we check the
 * signed "user verified" flag ourselves, for registration and for every sign-in.
 */
export function requireUserVerified(userVerified: boolean): void {
  if (!userVerified) {
    throw new APIError("UNAUTHORIZED", {
      message: "The passkey did not verify you (PIN, fingerprint or face)",
      code: "USER_VERIFICATION_REQUIRED",
    });
  }
}

/** The longest name a person can give a passkey. */
export const PASSKEY_NAME_MAX = 60;

/** A clean passkey name: control characters removed, spaces collapsed, at most 60 characters. */
export function cleanPasskeyName(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const visible = [...raw].map((char) => {
    const code = char.codePointAt(0) ?? 0;
    return code < 0x20 || code === 0x7f ? " " : char;
  });
  const name = visible.join("").replace(/\s+/g, " ").trim();
  return name === "" ? null : [...name].slice(0, PASSKEY_NAME_MAX).join("");
}

/**
 * The relying party of the passkeys, derived from the configured public URL and nothing else:
 * never from a request header, so a forged Host or Origin cannot move the trust boundary.
 * A passkey is bound to this RP ID and origin by the browser and the authenticator, which is
 * what makes a look-alike site unable to use it (phishing resistance).
 */
export function relyingParty(publicUrl: string): { rpID: string; origin: string; usable: boolean } {
  const url = new URL(publicUrl);
  const rpID = url.hostname;
  // An RP ID is a domain: an IP address is refused by browsers. Browsers also need a secure context.
  const isIp = /^\[.*\]$/.test(rpID) || /^\d{1,3}(\.\d{1,3}){3}$/.test(rpID);
  const secure = url.protocol === "https:" || rpID === "localhost";
  return { rpID, origin: url.origin, usable: !isIp && secure };
}

/**
 * Options of better-auth's passkey plugin (ADR 0017). `onUsed` runs after a passkey signed in
 * and passed the user-verification check, e.g. to record "last used".
 */
export function passkeyOptions(
  publicUrl: string,
  onUsed: (credentialId: string) => Promise<void>,
): PasskeyOptions {
  const rp = relyingParty(publicUrl);
  return {
    rpID: rp.rpID,
    rpName: "GarnetOps",
    origin: rp.origin,
    // Discoverable credentials (sign-in without typing an address) with user verification.
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    registration: {
      requireSession: true,
      afterVerification: ({ verification }) => {
        requireUserVerified(verification.registrationInfo?.userVerified === true);
      },
    },
    authentication: {
      afterVerification: async ({ verification, clientData }) => {
        requireUserVerified(verification.authenticationInfo.userVerified);
        await onUsed(clientData.id);
      },
    },
  };
}
