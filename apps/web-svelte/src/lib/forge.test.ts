import { describe, expect, it } from "vitest";
import { forgeOf } from "./forge.ts";

describe("forgeOf", () => {
  it("names the well-known forges", () => {
    expect(forgeOf("https://github.com/acme/app.git")).toBe("GitHub");
    expect(forgeOf("git@gitlab.com:acme/app.git")).toBe("GitLab");
    expect(forgeOf("https://token@codeberg.org/acme/app")).toBe("Codeberg");
  });

  it("shows the host name of a self-hosted forge", () => {
    expect(forgeOf("https://git.example.com:8443/team/app.git")).toBe("git.example.com");
    expect(forgeOf("ssh://git@Forgejo.Example.com:2222/team/app.git")).toBe("forgejo.example.com");
    expect(forgeOf("git@git.example.test:team/app.git")).toBe("git.example.test");
  });
});
