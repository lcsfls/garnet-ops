import { describe, expect, it } from "vitest";
import { camelCode, defaultApiBase, isBusy, repoHost, safeHttpsUrl } from "./fixes.ts";

describe("fix helpers", () => {
  it("turns reason codes into message keys", () => {
    expect(camelCode("edit-complex-range")).toBe("editComplexRange");
    expect(camelCode("manifest-changed")).toBe("manifestChanged");
    expect(camelCode("unexpected")).toBe("unexpected");
  });
  it("links only plain https addresses", () => {
    expect(safeHttpsUrl("https://git.example.com/team/app/pulls/7")).toBe(
      "https://git.example.com/team/app/pulls/7",
    );
    for (const bad of [
      null,
      "",
      "javascript:alert(1)",
      "http://git.example.com/x",
      "https://user:pw@git.example.com/x",
      "data:text/html,x",
      "//evil.example",
    ]) {
      expect(safeHttpsUrl(bad), String(bad)).toBeNull();
    }
  });
  it("knows when to keep polling", () => {
    expect(isBusy("queued")).toBe(true);
    expect(isBusy("running")).toBe(true);
    expect(isBusy("open")).toBe(false);
    expect(isBusy(undefined)).toBe(false);
  });
  it("derives the forge API address from the repository address", () => {
    expect(repoHost("https://GitHub.com/team/app.git")).toBe("github.com");
    expect(repoHost("git@ghe.example.lan:team/app.git")).toBe("ghe.example.lan");
    expect(repoHost("ssh://git@git.example.lan:2222/team/app")).toBe("git.example.lan");
    expect(repoHost("nonsense")).toBeNull();
    expect(defaultApiBase("github", "github.com")).toBe("https://api.github.com");
    expect(defaultApiBase("github", "ghe.example.lan")).toBe("https://ghe.example.lan/api/v3");
    expect(defaultApiBase("gitea", "git.example.lan:3000")).toBe("https://git.example.lan:3000/api/v1");
  });
});
