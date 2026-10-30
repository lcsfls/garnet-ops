import { describe, expect, it } from "vitest";
import {
  authorizeUrl,
  hashSignInState,
  newSignInSecret,
  pkceChallenge,
  signInFlow,
  signInRedirectUri,
} from "./forge-sign-in.ts";

describe("signing in to a forge (ADR 0031)", () => {
  it("uses the device flow for GitHub and the code flow with PKCE for Gitea and Forgejo", () => {
    expect(signInFlow("github")).toBe("device");
    expect(signInFlow("gitea")).toBe("code");
    expect(signInFlow("forgejo")).toBe("code");
  });

  it("makes long random secrets and the S256 challenge of RFC 7636", () => {
    const a = newSignInSecret();
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(newSignInSecret()).not.toBe(a);
    // The example of RFC 7636, appendix B.
    expect(pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe(
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
    expect(hashSignInState("x")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("builds the authorize address with the fixed redirect address and read scopes", () => {
    const redirectUri = signInRedirectUri("https://garnetops.example.lan/");
    expect(redirectUri).toBe("https://garnetops.example.lan/settings/accounts/callback");
    const url = new URL(
      authorizeUrl({
        kind: "forgejo",
        webBaseUrl: "https://git.example.lan/forge",
        clientId: "abc-123",
        redirectUri,
        state: "s",
        challenge: "c",
      }),
    );
    expect(url.origin + url.pathname).toBe("https://git.example.lan/forge/login/oauth/authorize");
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: "abc-123",
      redirect_uri: redirectUri,
      response_type: "code",
      state: "s",
      code_challenge: "c",
      code_challenge_method: "S256",
      scope: "read:repository read:user",
    });
  });

  it("asks for the write scope only when asked to (ADR 0039)", () => {
    const base = {
      webBaseUrl: "https://git.example.lan",
      clientId: "abc-123",
      redirectUri: "https://garnetops.example.test/settings/accounts/callback",
      state: "s",
      challenge: "c",
    };
    const scope = (url: string) => new URL(url).searchParams.get("scope");
    expect(scope(authorizeUrl({ ...base, kind: "gitea", write: true }))).toBe("write:repository read:user");
    expect(scope(authorizeUrl({ ...base, kind: "forgejo", write: true }))).toBe("write:repository read:user");
    expect(scope(authorizeUrl({ ...base, kind: "gitea", write: false }))).toBe("read:repository read:user");
    expect(scope(authorizeUrl({ ...base, kind: "gitea" }))).toBe("read:repository read:user");
    // GitHub Apps take their permissions from the registration: no scope either way.
    expect(scope(authorizeUrl({ ...base, kind: "github", write: true }))).toBeNull();
  });
});
