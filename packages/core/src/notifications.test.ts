import { describe, expect, test } from "vitest";
import {
  channelAccepts,
  channelFiltersSchema,
  countFrom,
  escapeDiscord,
  isForbiddenAddress,
  type NotifyPayload,
  webhookBody,
  webhookUrlProblem,
} from "./notifications.ts";

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
      allowed_mentions: unknown;
      embeds: { description: string }[];
    };
    expect(body.allowed_mentions).toEqual({ parse: [] });
    expect(body.embeds[0]?.description).toContain(payload.link);
  });
  test("Discord: one embed that links to GarnetOps, in the event's colour, with markdown kept as text", () => {
    const body = webhookBody(
      "discord",
      { ...payload, repository: { id: "repo_1", name: "**evil** [x](https://example.net)" } },
      "New critical vulnerabilities: **evil** [x](https://example.net)",
      "New in the last scan: 2 critical.",
    ) as {
      embeds: { title: string; url: string; color: number; timestamp: string; footer: { text: string } }[];
    };
    const [embed] = body.embeds;
    expect(embed?.url).toBe(payload.link);
    expect(embed?.title).toBe(
      "New critical vulnerabilities: \\*\\*evil\\*\\* \\[x\\]\\(https://example.net\\)",
    );
    expect(embed?.color).toBe(0xd9481f);
    expect(embed?.timestamp).toBe(payload.at);
    expect(embed?.footer.text).toBe("GarnetOps · Example");
    expect(escapeDiscord("a_b~c`d|e>f#g-h")).toBe("a\\_b\\~c\\`d\\|e\\>f\\#g\\-h");
  });
  test("Discord embeds stay within Discord's limits", () => {
    const body = webhookBody("discord", payload, "T".repeat(400), "x".repeat(5000)) as {
      embeds: { title: string; description: string }[];
    };
    expect(body.embeds[0]?.title.length).toBe(256);
    expect(body.embeds[0]?.description.length).toBe(4096);
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

describe("channel filters", () => {
  const base: NotifyPayload = {
    event: "finding.new",
    organization: "Example",
    repository: { id: "repo_1", name: "app" },
    findings: { critical: 0, high: 0, medium: 2, low: 5 },
    link: "https://garnetops.example.com/repositories/repo_1",
    at: "2026-10-21T10:00:00.000Z",
  };
  test("new findings count from the channel's minimum severity on, high by default", () => {
    expect(channelAccepts({}, base)).toBe(false);
    expect(channelAccepts({ minSeverity: "medium" }, base)).toBe(true);
    expect(
      channelAccepts(
        { minSeverity: "critical" },
        { ...base, findings: { critical: 1, high: 0, medium: 2, low: 5 } },
      ),
    ).toBe(true);
    expect(countFrom(base.findings, "low")).toBe(7);
    expect(countFrom(undefined, "low")).toBe(0);
  });
  test("a repository filter lets only those repositories through; a test message always goes", () => {
    const gate: NotifyPayload = { ...base, event: "gate.blocked", gate: { blockingRules: 1 } };
    expect(channelAccepts({ repositoryIds: ["repo_2"] }, gate)).toBe(false);
    expect(channelAccepts({ repositoryIds: ["repo_1", "repo_2"] }, gate)).toBe(true);
    expect(channelAccepts({ repositoryIds: [] }, gate)).toBe(true);
    expect(channelAccepts({ repositoryIds: ["repo_2"] }, { ...gate, event: "test", repository: null })).toBe(
      true,
    );
  });
  test("filters are validated", () => {
    expect(channelFiltersSchema.safeParse({ minSeverity: "negligible" }).success).toBe(false);
    expect(channelFiltersSchema.safeParse({ repositoryIds: Array(201).fill("r") }).success).toBe(false);
    expect(channelFiltersSchema.parse({})).toEqual({});
  });
});
