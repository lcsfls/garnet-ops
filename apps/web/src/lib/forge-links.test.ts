import { describe, expect, it } from "vitest";
import { forgeRepo, newFileUrl, secretsUrl } from "./forge-links.ts";

describe("forgeRepo", () => {
  it("reads https and ssh addresses with owner and name", () => {
    expect(forgeRepo("https://github.com/acme/app.git")).toEqual({
      base: "https://github.com",
      owner: "acme",
      name: "app",
      kind: "github",
    });
    expect(forgeRepo("git@git.example.com:team/service.git")).toMatchObject({
      base: "https://git.example.com",
      kind: "gitea-or-forgejo",
    });
    expect(forgeRepo("ssh://git@git.example.com:2222/team/service.git")).toMatchObject({
      base: "https://git.example.com",
      owner: "team",
      name: "service",
    });
  });

  it("gives no links for paths it cannot be sure about", () => {
    expect(forgeRepo("https://gitlab.example.com/group/sub/app.git")).toBeNull();
    expect(forgeRepo("file:///srv/app")).toBeNull();
    expect(forgeRepo("not a url")).toBeNull();
  });
});

describe("links", () => {
  const gh = forgeRepo("https://github.com/acme/app") as NonNullable<ReturnType<typeof forgeRepo>>;
  const gitea = forgeRepo("https://git.example.com/team/app") as NonNullable<ReturnType<typeof forgeRepo>>;
  it("points at the secrets page of each forge", () => {
    expect(secretsUrl(gh)).toBe("https://github.com/acme/app/settings/secrets/actions/new");
    expect(secretsUrl(gitea)).toBe("https://git.example.com/team/app/settings/actions/secrets");
  });
  it("fills in a new file on GitHub only", () => {
    const url = newFileUrl(gh, "main", ".github/workflows/x.yml", "a: 1");
    expect(url).toBe(
      "https://github.com/acme/app/new/main?filename=.github%2Fworkflows%2Fx.yml&value=a%3A+1",
    );
    expect(newFileUrl(gitea, "main", "x", "y")).toBeNull();
  });
});
