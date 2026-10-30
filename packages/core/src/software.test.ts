import { describe, expect, it } from "vitest";
import type { EolCycle } from "./eol-data.ts";
import {
  compareVersions,
  detectSoftware,
  judgeSoftware,
  metaGenerators,
  softwareSeverity,
} from "./software.ts";

const NOW = new Date("2026-10-30T12:00:00Z");
const DATA: Record<string, EolCycle[]> = {
  php: [
    { cycle: "8.3", eol: "2027-12-31", latest: "8.3.36" },
    { cycle: "8.1", eol: "2025-12-31", latest: "8.1.34" },
  ],
  wordpress: [
    { cycle: "6.4", eol: false, latest: "6.4.7" },
    { cycle: "4.0", eol: true, latest: "4.0.38" },
  ],
  nginx: [{ cycle: "1.26", eol: "2025-04-23", latest: "1.26.3" }],
};

describe("software a website names about itself (ADR 0038)", () => {
  it("reads the generator tags of a page, in any attribute order, as cut text only", () => {
    const html = `<html><head>
      <meta name="generator" content="WordPress 6.4.2" />
      <meta content='Astro v4.5.0' name='generator'>
      <meta name="description" content="not this">
      <meta name="generator" content="Evil‮ <script>alert(1)</script> ${"x".repeat(400)}">
    </head>`;
    const found = metaGenerators(html);
    expect(found.slice(0, 2)).toEqual(["WordPress 6.4.2", "Astro v4.5.0"]);
    expect(found).toHaveLength(2);
    expect(metaGenerators("<p>no tags</p>")).toEqual([]);
  });

  it("finds products and versions in the headers and generator tags, the first source per product", () => {
    expect(
      detectSoftware({
        headers: { server: "nginx/1.26.1", "x-powered-by": "PHP/8.1.2" },
        generators: ["WordPress 6.4.2", "Drupal 10 (https://www.drupal.org)", "TYPO3 CMS"],
      }),
    ).toEqual([
      { product: "nginx", version: "1.26.1", source: "server" },
      { product: "php", version: "8.1.2", source: "x-powered-by" },
      { product: "wordpress", version: "6.4.2", source: "generator" },
      { product: "drupal", version: "10", source: "generator" },
    ]);
    expect(detectSoftware({ headers: { server: "Apache" } })).toEqual([]);
    // A snapshot of an older version without headers or generators.
    expect(detectSoftware({})).toEqual([]);
  });

  it("does not judge a distribution's build: its number says nothing about backported fixes", () => {
    const found = detectSoftware({
      headers: { server: "Apache/2.4.57 (Debian)", "x-powered-by": "PHP/8.1.2-1ubuntu2.14" },
    });
    expect(found.map((f) => [f.product, f.distribution])).toEqual([
      ["apache-http-server", true],
      ["php", true],
    ]);
    expect(found.map((f) => judgeSoftware(f, NOW, DATA).status)).toEqual(["distribution", "distribution"]);
    expect(detectSoftware({ headers: { "x-powered-by": "PHP/8.1.2" } })[0]?.distribution).toBeUndefined();
  });

  it("counts a CMS's own version fully and a server header one step lower", () => {
    const at = (source: "generator" | "server", product: "php" | "wordpress", version: string) =>
      softwareSeverity(judgeSoftware({ product, version, source }, NOW, DATA));
    expect(at("generator", "wordpress", "4.0.1")).toBe("high");
    expect(at("generator", "wordpress", "6.4.2")).toBe("medium");
    expect(at("server", "php", "8.1.2")).toBe("medium");
    expect(at("server", "php", "8.3.10")).toBe("low");
    expect(at("server", "php", "8.3.36")).toBeNull();
  });

  it("calls a line without fixes end of life, a version behind its line outdated, the latest current", () => {
    const judge = (product: "php" | "wordpress" | "nginx", version: string) =>
      judgeSoftware({ product, version, source: "server" }, NOW, DATA);
    expect(judge("php", "8.1.2")).toMatchObject({ status: "endOfLife", cycle: "8.1", eol: "2025-12-31" });
    expect(judge("php", "8.3.10")).toMatchObject({ status: "outdated", latest: "8.3.36" });
    expect(judge("php", "8.3.36").status).toBe("current");
    expect(judge("wordpress", "6.4.2")).toMatchObject({ status: "outdated", latest: "6.4.7" });
    expect(judge("wordpress", "4.0.1").status).toBe("endOfLife");
    expect(judge("nginx", "1.26.1").status).toBe("endOfLife");
    // A version that names no line, or a product without data, is not judged.
    expect(judge("php", "7.4.3").status).toBe("unknown");
    expect(judgeSoftware({ product: "astro", version: "4.5.0", source: "generator" }, NOW, DATA).status).toBe(
      "unknown",
    );
    // "6.4" alone says nothing about the patch level: not called outdated.
    expect(judge("wordpress", "6.4").status).toBe("current");
  });

  it("compares versions by their numbers", () => {
    expect(compareVersions("8.3.10", "8.3.9")).toBeGreaterThan(0);
    expect(compareVersions("1.26", "1.26.0")).toBe(0);
    expect(compareVersions("6.4.2", "6.4.7")).toBeLessThan(0);
  });
});
