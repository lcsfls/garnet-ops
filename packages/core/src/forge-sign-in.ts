/**
 * Signing in to a forge (ADR 0031): which flow a forge uses, the scopes asked for, and the PKCE and state values of the
 * authorization code flow. Pure functions; the worker talks to the forge, the API keeps the state.
 */
import { createHash, randomBytes } from "node:crypto";
import type { ForgeKind } from "./fix-prs.ts";

/** GitHub (GitHub Apps) signs in with the device flow; Gitea and Forgejo with the authorization code and PKCE. */
export type SignInFlow = "device" | "code";
export const signInFlow = (kind: ForgeKind): SignInFlow => (kind === "github" ? "device" : "code");

/** Read only. A GitHub App's permissions come from its registration, so GitHub asks for no scope. */
export const SIGN_IN_SCOPES: Record<ForgeKind, string> = {
  github: "",
  gitea: "read:repository read:user",
  forgejo: "read:repository read:user",
};

/**
 * With write access, for fix pull requests in the person's own name (ADR 0039). GitHub has no scopes: the App's
 * registration grants "Contents" and "Pull requests" read and write, or not.
 */
export const SIGN_IN_WRITE_SCOPES: Record<ForgeKind, string> = {
  github: "",
  gitea: "write:repository read:user",
  forgejo: "write:repository read:user",
};

/** Where Gitea and Forgejo send the browser back to, below PUBLIC_URL. */
export const SIGN_IN_CALLBACK_PATH = "/settings/accounts/callback";

/** How long a sign-in may take before it has to start again. */
export const SIGN_IN_TTL_MS = 10 * 60_000;
/** The longest a device flow is polled, whatever the forge says. */
export const DEVICE_FLOW_MAX_MS = 15 * 60_000;

const base64url = (bytes: Buffer) => bytes.toString("base64url");

/** 256 random bits, as the `state` the browser carries, and as the code verifier (RFC 7636: 43 to 128 characters). */
export const newSignInSecret = (): string => base64url(randomBytes(32));

/** The S256 code challenge of a verifier. */
export const pkceChallenge = (verifier: string): string =>
  base64url(createHash("sha256").update(verifier).digest());

/** What is stored of a state: its hash, so a database dump cannot finish someone's sign-in. */
export const hashSignInState = (state: string): string => createHash("sha256").update(state).digest("hex");

/** The redirect address of an installation: PUBLIC_URL without trailing slash, plus the callback path. */
export const signInRedirectUri = (publicUrl: string): string =>
  `${publicUrl.replace(/\/+$/, "")}${SIGN_IN_CALLBACK_PATH}`;

/** The forge's authorize page for the authorization code flow (Gitea, Forgejo). */
export function authorizeUrl(input: {
  kind: ForgeKind;
  webBaseUrl: string;
  clientId: string;
  redirectUri: string;
  state: string;
  challenge: string;
  /** Ask for the write scope (ADR 0039) instead of the read-only one. */
  write?: boolean;
}): string {
  const url = new URL(`${input.webBaseUrl.replace(/\/+$/, "")}/login/oauth/authorize`);
  url.searchParams.set("client_id", input.clientId);
  url.searchParams.set("redirect_uri", input.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", input.state);
  url.searchParams.set("code_challenge", input.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  const scope = (input.write ? SIGN_IN_WRITE_SCOPES : SIGN_IN_SCOPES)[input.kind];
  if (scope) url.searchParams.set("scope", scope);
  return url.toString();
}

/** A client id as forges issue them: printable, no spaces, no URL syntax. */
export const CLIENT_ID_PATTERN = /^[A-Za-z0-9._-]{4,200}$/;
