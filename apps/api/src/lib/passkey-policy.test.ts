import { describe, expect, it } from "vitest";
import {
  cleanPasskeyName,
  PASSKEY_NAME_MAX,
  passkeyOptions,
  relyingParty,
  requireUserVerified,
} from "./passkey-policy.ts";

describe("requireUserVerified", () => {
  it("lets a verified authenticator through", () => {
    expect(() => requireUserVerified(true)).not.toThrow();
  });

  it("refuses an authenticator that did not verify the person", () => {
    expect(() => requireUserVerified(false)).toThrow(/did not verify/);
  });
});

describe("relyingParty", () => {
  it("derives RP ID and origin from the public URL only", () => {
    expect(relyingParty("https://garnetops.example.com/some/path")).toEqual({
      rpID: "garnetops.example.com",
      origin: "https://garnetops.example.com",
      usable: true,
    });
  });

  it("keeps the port in the origin but not in the RP ID", () => {
    expect(relyingParty("https://garnetops.example.lan:8443")).toEqual({
      rpID: "garnetops.example.lan",
      origin: "https://garnetops.example.lan:8443",
      usable: true,
    });
  });

  it("allows localhost over plain http for development", () => {
    expect(relyingParty("http://localhost:5173")).toEqual({
      rpID: "localhost",
      origin: "http://localhost:5173",
      usable: true,
    });
  });

  it("marks addresses and plain http hosts as unusable for passkeys", () => {
    expect(relyingParty("https://192.0.2.10").usable).toBe(false);
    expect(relyingParty("https://[2001:db8::1]").usable).toBe(false);
    expect(relyingParty("http://garnetops.example.lan").usable).toBe(false);
  });
});

describe("cleanPasskeyName", () => {
  it("trims, collapses spaces and drops control characters", () => {
    expect(cleanPasskeyName("  Work   laptop\n\t ")).toBe("Work laptop");
    expect(cleanPasskeyName("a\u0000b")).toBe("a b");
  });

  it("limits the length by characters", () => {
    expect(cleanPasskeyName("x".repeat(200))).toHaveLength(PASSKEY_NAME_MAX);
  });

  it("treats empty and non-text input as no name", () => {
    expect(cleanPasskeyName("   ")).toBeNull();
    expect(cleanPasskeyName(undefined)).toBeNull();
    expect(cleanPasskeyName(42)).toBeNull();
  });
});

describe("passkeyOptions", () => {
  const used: string[] = [];
  const options = passkeyOptions("https://garnetops.example.com", async (id) => {
    used.push(id);
  });
  const registration = options.registration?.afterVerification;
  const authentication = options.authentication?.afterVerification;

  it("binds passkeys to the public URL and asks for user verification", () => {
    expect(options.rpID).toBe("garnetops.example.com");
    expect(options.origin).toBe("https://garnetops.example.com");
    expect(options.authenticatorSelection).toMatchObject({
      userVerification: "required",
      residentKey: "required",
    });
    expect(options.registration?.requireSession).toBe(true);
  });

  it("refuses to register a passkey the authenticator did not verify", async () => {
    const verification = (userVerified: boolean) => ({ registrationInfo: { userVerified } }) as never;
    const register = async (v: never) => registration?.({ verification: v } as never);
    await expect(register(verification(false))).rejects.toThrow();
    await expect(register(verification(true))).resolves.toBeUndefined();
    // Missing registration info is as bad as a missing verification.
    await expect(register({} as never)).rejects.toThrow();
  });

  it("refuses a sign-in without user verification and records only verified ones", async () => {
    const verification = (userVerified: boolean) => ({ authenticationInfo: { userVerified } }) as never;
    await expect(
      authentication?.({ verification: verification(false), clientData: { id: "cred-a" } } as never),
    ).rejects.toThrow();
    expect(used).toEqual([]);
    await authentication?.({ verification: verification(true), clientData: { id: "cred-b" } } as never);
    expect(used).toEqual(["cred-b"]);
  });
});
