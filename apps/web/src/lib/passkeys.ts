import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
  WebAuthnError,
} from "@simplewebauthn/browser";
import type { MessageKey } from "./i18n.ts";

/**
 * The browser side of passkeys (ADR 0017). The server is better-auth's passkey plugin; the
 * ceremonies are run here with SimpleWebAuthn so the passkey's name stays out of what the
 * authenticator shows (it lists the account's address, not the label) and so user
 * verification is always asked for. The server checks the signed "user verified" flag itself,
 * so this client-side setting is a convenience, not the control.
 */

export type PasskeyFailure =
  | "unsupported"
  | "cancelled"
  | "step-up"
  | "not-verified"
  | "already-registered"
  | "unknown-passkey"
  | "rate-limited"
  | "failed";

export type PasskeyResult = { ok: true } | { ok: false; reason: PasskeyFailure };

export const passkeysSupported = (): boolean => typeof window !== "undefined" && browserSupportsWebAuthn();

/** Translated text for a failure, e.g. under the "Add a passkey" button. */
export const PASSKEY_FAILURE_KEYS: Record<PasskeyFailure, MessageKey> = {
  unsupported: "account.passkeys.errorUnsupported",
  cancelled: "account.passkeys.errorCancelled",
  "step-up": "errors.generic",
  "not-verified": "account.passkeys.errorNotVerified",
  "already-registered": "account.passkeys.errorAlreadyRegistered",
  "unknown-passkey": "account.passkeys.errorUnknown",
  "rate-limited": "errors.tooManyAttempts",
  failed: "errors.generic",
};

const BASE = "/api/auth/passkey";

async function json(path: string, init?: RequestInit): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`${BASE}${path}`, {
    credentials: "same-origin",
    ...init,
    headers: { accept: "application/json", ...(init?.body ? { "content-type": "application/json" } : {}) },
  });
  const body: unknown = await res.json().catch(() => null);
  return { status: res.status, body };
}

function failureOf(status: number, body: unknown): PasskeyFailure {
  const code = (body as { code?: string } | null)?.code;
  if (status === 429) return "rate-limited";
  if (code === "STEP_UP_REQUIRED") return "step-up";
  if (code === "USER_VERIFICATION_REQUIRED") return "not-verified";
  if (code === "PASSKEY_NOT_FOUND") return "unknown-passkey";
  return "failed";
}

function failureOfCeremony(error: unknown): PasskeyFailure {
  if (error instanceof WebAuthnError) {
    if (error.code === "ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED") return "already-registered";
    if (error.code === "ERROR_CEREMONY_ABORTED") return "cancelled";
  }
  // The browser reports a closed or refused prompt as NotAllowedError.
  if (error instanceof Error && (error.name === "NotAllowedError" || error.name === "AbortError")) {
    return "cancelled";
  }
  return "failed";
}

/** Adds a passkey to the signed-in account (a recent sign-in is needed; the server says so with "step-up"). */
export async function registerPasskey(name: string): Promise<PasskeyResult> {
  if (!passkeysSupported()) return { ok: false, reason: "unsupported" };
  const options = await json("/generate-register-options");
  if (options.status !== 200) return { ok: false, reason: failureOf(options.status, options.body) };
  const optionsJSON = options.body as Parameters<typeof startRegistration>[0]["optionsJSON"];
  optionsJSON.authenticatorSelection = {
    ...optionsJSON.authenticatorSelection,
    userVerification: "required",
  };
  let response: Awaited<ReturnType<typeof startRegistration>>;
  try {
    response = await startRegistration({ optionsJSON });
  } catch (error) {
    return { ok: false, reason: failureOfCeremony(error) };
  }
  const { clientExtensionResults: _unused, ...body } = response;
  const verified = await json("/verify-registration", {
    method: "POST",
    body: JSON.stringify({ response: body, name }),
  });
  return verified.status === 200
    ? { ok: true }
    : { ok: false, reason: failureOf(verified.status, verified.body) };
}

/** Signs in with a passkey: a discoverable credential, so no address is typed. Needs no password and no code. */
export async function signInWithPasskey(): Promise<PasskeyResult> {
  if (!passkeysSupported()) return { ok: false, reason: "unsupported" };
  const options = await json("/generate-authenticate-options");
  if (options.status !== 200) return { ok: false, reason: failureOf(options.status, options.body) };
  const optionsJSON = options.body as Parameters<typeof startAuthentication>[0]["optionsJSON"];
  optionsJSON.userVerification = "required";
  let response: Awaited<ReturnType<typeof startAuthentication>>;
  try {
    response = await startAuthentication({ optionsJSON });
  } catch (error) {
    return { ok: false, reason: failureOfCeremony(error) };
  }
  const { clientExtensionResults: _unused, ...body } = response;
  const verified = await json("/verify-authentication", {
    method: "POST",
    body: JSON.stringify({ response: body }),
  });
  return verified.status === 200
    ? { ok: true }
    : { ok: false, reason: failureOf(verified.status, verified.body) };
}
