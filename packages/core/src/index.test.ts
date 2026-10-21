import { describe, expect, it } from "vitest";
import { newId, repoUrlSchema } from "./index.ts";

describe("repoUrlSchema", () => {
  it.each([
    "https://github.com/example-org/app.git",
    "https://git.example.lan/team/billing-portal",
    "git@github.com:example-org/website.git",
    "ssh://git@git.example.lan:2222/team/booking-app.git",
  ])("accepts %s", (url) => {
    expect(repoUrlSchema.safeParse(url).success).toBe(true);
  });

  it.each([
    "http://github.com/a/b",
    "https://user:pass@github.com/a/b",
    "https://token@github.com/a/b",
    "file:///etc/passwd",
    "/srv/git/repo",
    "ext::sh -c touch% /tmp/pwned",
    "-oProxyCommand=evil@host:repo",
    "ssh://-oProxyCommand=x/repo",
    "git@-host:repo",
    "git@host:-repo",
  ])("rejects %s", (url) => {
    expect(repoUrlSchema.safeParse(url).success).toBe(false);
  });
});

describe("newId", () => {
  it("is prefixed, URL-safe and unique", () => {
    const ids = new Set(Array.from({ length: 1000 }, () => newId("fnd")));
    expect(ids.size).toBe(1000);
    for (const id of ids) expect(id).toMatch(/^fnd_[0-9a-z]{20}$/);
  });
});
