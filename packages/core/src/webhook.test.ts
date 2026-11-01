import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { signatureMatches, webhookHeaders, webhookIntent } from "./webhook.ts";

const SECRET = "s".repeat(43);
const body = Buffer.from(JSON.stringify({ ref: "refs/heads/main" }));
const hex = createHmac("sha256", SECRET).update(body).digest("hex");
const headers = (h: Record<string, string>) => (name: string) => h[name];

describe("webhookHeaders", () => {
  it("reads GitHub's headers", () => {
    expect(
      webhookHeaders(headers({ "x-github-event": "push", "x-hub-signature-256": `sha256=${hex}` })),
    ).toEqual({
      event: "push",
      signature: hex,
    });
  });

  it("reads Gitea's and Forgejo's own headers", () => {
    expect(
      webhookHeaders(headers({ "x-gitea-event": "push", "x-gitea-signature": hex.toUpperCase() })),
    ).toEqual({
      event: "push",
      signature: hex,
    });
    expect(webhookHeaders(headers({ "x-forgejo-event": "ping", "x-forgejo-signature": hex }))).toEqual({
      event: "ping",
      signature: hex,
    });
  });

  it("refuses what is not an event name or a SHA-256 in hex", () => {
    expect(
      webhookHeaders(headers({ "x-github-event": "push; drop", "x-hub-signature-256": "sha1=abc" })),
    ).toEqual({
      event: null,
      signature: null,
    });
    expect(webhookHeaders(headers({}))).toEqual({ event: null, signature: null });
  });
});

describe("signatureMatches", () => {
  it("accepts the HMAC of the exact body only", () => {
    expect(signatureMatches(SECRET, body, hex)).toBe(true);
    expect(signatureMatches(SECRET, Buffer.from(`${body} `), hex)).toBe(false);
    expect(signatureMatches("t".repeat(43), body, hex)).toBe(false);
    expect(signatureMatches(SECRET, body, null)).toBe(false);
    expect(signatureMatches(SECRET, body, "ab")).toBe(false);
  });
});

describe("webhookIntent", () => {
  const push = (ref: string, extra: Record<string, unknown> = {}) => ({
    ref,
    repository: { default_branch: "main" },
    ...extra,
  });

  it("scans a push to the branch GarnetOps scans", () => {
    expect(webhookIntent("push", push("refs/heads/release"), "release")).toBe("scan");
    // No branch set: the default branch the forge names.
    expect(webhookIntent("push", push("refs/heads/main"), null)).toBe("scan");
  });

  it("ignores other branches, tags, deleted branches and other events", () => {
    expect(webhookIntent("push", push("refs/heads/feature"), null)).toBe("ignored-branch");
    expect(webhookIntent("push", push("refs/tags/v1.0.0"), "main")).toBe("ignored-branch");
    expect(webhookIntent("push", push("refs/heads/main", { deleted: true }), null)).toBe("ignored-delete");
    expect(webhookIntent("issues", {}, null)).toBe("ignored-event");
    expect(webhookIntent(null, {}, null)).toBe("ignored-event");
    expect(webhookIntent("ping", null, null)).toBe("ping");
  });

  it("calls a payload it cannot understand unreadable", () => {
    expect(webhookIntent("push", "not an object", "main")).toBe("unreadable");
    expect(webhookIntent("push", { ref: 42 }, "main")).toBe("unreadable");
    expect(webhookIntent("push", { ref: "refs/heads/main" }, null)).toBe("unreadable");
  });
});
