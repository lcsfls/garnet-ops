import { describe, expect, it } from "vitest";
import { parseWordPressOrgVersion, wordpressAssets, wordpressOrgPath } from "./wordpress.ts";

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
