import { describe, expect, test } from "vitest";
import { isForbiddenAddress, type NotifyPayload, webhookBody, webhookUrlProblem } from "./notifications.ts";

describe("isForbiddenAddress", () => {
  test.each([
    "127.0.0.1",
    "127.5.5.5",
    "0.0.0.0",
    "169.254.169.254",
    "224.0.0.1",
    "255.255.255.255",
    "100.100.100.200",
    "::1",
    "::",
    "fe80::1",
    "ff02::1",
    "::ffff:127.0.0.1",
    "::ffff:169.254.169.254",
    "fd00:ec2::254",
    // Other notations of loopback and metadata: IPv4-mapped in hex, expanded, IPv4-compatible.
    "::ffff:7f00:1",
    "::ffff:a9fe:a9fe",
    "0:0:0:0:0:0:0:1",
    "::127.0.0.1",
    "64:ff9b::7f00:1",
    "2002:7f00:1::1",
    "not-an-ip",
  ])("refuses %s", (address) => {
    expect(isForbiddenAddress(address)).toBe(true);
  });
  test.each([
    "10.0.0.5",
    "192.168.1.20",
    "172.16.3.4",
    "192.0.2.10",
    "8.8.8.8",
    "2001:db8::1",
    "fd12:3456::1",
  ])("allows %s", (address) => {
    expect(isForbiddenAddress(address)).toBe(false);
  });
});

describe("webhookUrlProblem", () => {
  test("refuses IPv6 literals that hide loopback or metadata", () => {
    // The URL parser rewrites [::ffff:127.0.0.1] to [::ffff:7f00:1].
    expect(webhookUrlProblem("https://[::ffff:127.0.0.1]/x")).not.toBeNull();
    expect(webhookUrlProblem("https://[::ffff:a9fe:a9fe]/x")).not.toBeNull();
    expect(webhookUrlProblem("https://[0:0:0:0:0:0:0:1]/x")).not.toBeNull();
  });

  test("https only, no credentials, no loopback or metadata literals", () => {
    expect(webhookUrlProblem("https://chat.example.com/hooks/abc")).toBeNull();
    expect(webhookUrlProblem("https://192.0.2.10/hook")).toBeNull();
    expect(webhookUrlProblem("http://chat.example.com/hook")).toMatch(/https/);
    expect(webhookUrlProblem("https://user:pw@chat.example.com/hook")).toMatch(/password/);
    expect(webhookUrlProblem("https://localhost/hook")).toMatch(/not allowed/);
    expect(webhookUrlProblem("https://169.254.169.254/latest")).toMatch(/not allowed/);
    expect(webhookUrlProblem("https://[::1]/hook")).toMatch(/not allowed/);
    expect(webhookUrlProblem("file:///etc/passwd")).toMatch(/https/);
    expect(webhookUrlProblem("nonsense")).toBe("Not a URL");
  });
});

describe("webhookBody", () => {
  const payload: NotifyPayload = {
    event: "finding.new_critical",
    organization: "Example",
    repository: { id: "repo_1", name: "@everyone billing" },
    counts: { critical: 2, knownExploited: 1 },
    link: "https://garnetops.example.com/repositories/repo_1",
    at: "2026-10-21T10:00:00.000Z",
  };
  test("Discord never pings anyone, whatever the repository is called", () => {
    const body = webhookBody("discord", payload, "New critical findings", "@everyone billing: 2") as {
      content: string;
      allowed_mentions: unknown;
    };
    expect(body.allowed_mentions).toEqual({ parse: [] });
    expect(body.content).toContain(payload.link);
  });
  test("Slack-compatible and generic shapes", () => {
    expect(webhookBody("slack", payload, "T", "x")).toEqual({ text: `*T*\nx\n<${payload.link}>` });
    expect(webhookBody("generic", payload, "T", "x")).toMatchObject({
      title: "T",
      text: "x",
      event: payload.event,
    });
  });
});
