import { describe, expect, it } from "vitest";
import {
  affectsVersion,
  parseWordfenceFeed,
  parseWordPressOrgVersion,
  wordpressAssets,
  wordpressOrgPath,
} from "./wordpress.ts";

describe("WordPress plugins and themes from asset addresses (ADR 0042)", () => {
  const page = `
    <link rel='stylesheet' href='https://www.example.com/wp-content/themes/twentytwentyfour/style.css?ver=1.2' />
    <link rel='stylesheet' href='https://www.example.com/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.9.3' />
    <script src="https://www.example.com/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.9.3"></script>
    <script src="https://cdn.example.net/wp-content/plugins/woocommerce/assets/js/frontend/cart.min.js?ver=8.7.0"></script>
    <script src="/wp-content/plugins/woocommerce/assets/js/other.js?ver=6.5.2"></script>
    <script src="/wp-content/plugins/no-version/a.js?ver=6.5.2"></script>
    <script src="/wp-content/plugins/Weird%20Slug/a.js?ver=1.0"></script>
    <script src="/wp-content/plugins/hostile/a.js?ver=<script>"></script>
  `;

  it("names plugins and themes by slug with the version most of their assets carry, never the WordPress version", () => {
    expect(wordpressAssets(page, "6.5.2")).toEqual({
      plugins: [
        { slug: "contact-form-7", version: "5.9.3" },
        { slug: "hostile", version: null },
        { slug: "no-version", version: null },
        { slug: "woocommerce", version: "8.7.0" },
      ],
      themes: [{ slug: "twentytwentyfour", version: "1.2" }],
    });
  });

  it("finds nothing on a page without WordPress assets, and keeps at most 60 plugins", () => {
    expect(wordpressAssets("<html><body>hello</body></html>")).toBeNull();
    const many = Array.from(
      { length: 80 },
      (_, i) => `<script src="/wp-content/plugins/p${i}/x.js"></script>`,
    ).join("");
    expect(wordpressAssets(many)?.plugins).toHaveLength(60);
  });
});

describe("latest versions from wordpress.org (ADR 0042, part 2)", () => {
  it("asks for one slug with every other field switched off, and refuses anything that is not a slug", () => {
    const path = wordpressOrgPath("plugin", "contact-form-7");
    expect(path).toMatch(
      /^\/plugins\/info\/1\.2\/\?action=plugin_information&request\[slug\]=contact-form-7&/,
    );
    expect(path).toContain("request[fields][sections]=0");
    expect(wordpressOrgPath("theme", "astra")).toMatch(/^\/themes\/info\/1\.2\/\?action=theme_information/);
    expect(() => wordpressOrgPath("plugin", "../admin")).toThrow();
  });

  it("reads only a version of the right shape", () => {
    expect(parseWordPressOrgVersion('{"name":"x","version":"5.9.8"}')).toBe("5.9.8");
    expect(parseWordPressOrgVersion('{"version":"<b>1</b>"}')).toBeNull();
    expect(parseWordPressOrgVersion("not json")).toBeNull();
  });
});

describe("advisories from the Wordfence feed (ADR 0042, part 3)", () => {
  const wanted = new Set(["plugin:contact-form-7", "core:wordpress"]);
  it("keeps only wanted slugs and fields of the right shape, and skips what does not fit", () => {
    const parsed = parseWordfenceFeed(
      {
        "a-1111-good": {
          id: "a-1111-good",
          title: "  XSS\u0007 in <b>Contact Form 7</b>  ",
          software: [
            {
              type: "plugin",
              slug: "contact-form-7",
              affected_versions: {
                "5.0 - 5.9.3": {
                  from_version: "5.0",
                  from_inclusive: true,
                  to_version: "5.9.3",
                  to_inclusive: false,
                },
                bad: { from_version: "<script>", to_version: "1" },
              },
              patched_versions: ["5.9.4", "<x>"],
            },
            {
              type: "plugin",
              slug: "akismet",
              affected_versions: { "*": { from_version: "*", to_version: "9" } },
            },
          ],
          cvss: { score: 11, rating: "Severe" },
          cve: "not-a-cve",
        },
        "b-2222-info": {
          id: "b-2222-info",
          informational: true,
          software: [{ type: "core", slug: "wordpress" }],
        },
        "../../etc": { id: "../../etc", software: [] },
        broken: "text",
      },
      wanted,
    );
    expect(parsed).toEqual([
      {
        id: "a-1111-good",
        kind: "plugin",
        slug: "contact-form-7",
        title: "XSS in <b>Contact Form 7</b>",
        cve: null,
        cvssScore: null,
        severity: "medium",
        affected: [{ from: "5.0", fromInclusive: true, to: "5.9.3", toInclusive: false }],
        patched: ["5.9.4"],
        published: null,
      },
    ]);
    expect(parseWordfenceFeed(null, wanted)).toEqual([]);
  });

  it("matches versions against open and closed ranges", () => {
    const range = { from: "5.0", fromInclusive: true, to: "5.9.3", toInclusive: false };
    expect(affectsVersion({ affected: [range] }, "5.0")).toBe(true);
    expect(affectsVersion({ affected: [range] }, "5.9.2")).toBe(true);
    expect(affectsVersion({ affected: [range] }, "5.9.3")).toBe(false);
    expect(affectsVersion({ affected: [range] }, "4.9")).toBe(false);
    expect(affectsVersion({ affected: [{ ...range, from: "*" }] }, "1.0")).toBe(true);
  });
});
