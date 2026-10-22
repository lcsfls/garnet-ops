import { resources } from "@garnetops/i18n";
import i18next from "i18next";
import ICU from "i18next-icu";
import { renderToStaticMarkup } from "react-dom/server";
import { I18nextProvider, initReactI18next } from "react-i18next";
import { describe, expect, it } from "vitest";
import { Markdown } from "./markdown.tsx";

// The app's own instance reads the browser; the renderer only needs the English texts.
const i18n = i18next.createInstance();
await i18n
  .use(ICU)
  .use(initReactI18next)
  .init({ resources, lng: "en", fallbackLng: "en", interpolation: { escapeValue: false } });

const html = (text: string) =>
  renderToStaticMarkup(
    <I18nextProvider i18n={i18n}>
      <Markdown text={text} />
    </I18nextProvider>,
  );

describe("Markdown renderer", () => {
  it("escapes raw HTML: a script tag is text, never an element", () => {
    const out = html(
      '<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>\n\n`<b>x</b>`\n\n```html\n<iframe src="javascript:alert(1)"></iframe>\n```',
    );
    expect(out).not.toContain("<script");
    expect(out).not.toContain("<img");
    expect(out).not.toContain("<iframe");
    expect(out).not.toContain("<b>");
    expect(out).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(out).toContain("&lt;iframe");
  });

  it("makes links only for http(s), with a safe rel and the host shown", () => {
    const out = html(
      "[advisory](https://advisories.example.com/x) and [bad](javascript:alert(1)) and [data](data:text/html,x)",
    );
    expect(out).toContain('href="https://advisories.example.com/x"');
    expect(out).toContain('rel="noopener noreferrer nofollow"');
    expect(out).toContain('target="_blank"');
    expect(out).toContain("(advisories.example.com)");
    expect(out).not.toContain('href="javascript');
    expect(out).not.toContain('href="data');
    expect(out.match(/<a /g)?.length).toBe(1);
  });

  it("never carries attributes the model controls: no style, no event handlers, no ids", () => {
    const out = html(
      '**bold** _it_ [x](https://example.com/" onmouseover="alert(1))\n\n- <a href="x" style="color:red">y</a>',
    );
    // Inside real tags only: the same words appear escaped in the text, which is harmless.
    expect(out).not.toMatch(/<[a-z][^>]*\s(on[a-z]+|style|id)=/i);
    expect(out).not.toMatch(/<[a-z][^>]*onmouseover/i);
  });

  it("shows entities as typed instead of decoding them into markup", () => {
    const out = html("&lt;script&gt; &amp; &#60;b&#62;");
    expect(out).toContain("&amp;lt;script&amp;gt;");
    expect(out).not.toContain("<script");
  });

  it("renders lists, emphasis and code blocks with a copy button", () => {
    const out = html("Intro **bold** and *italic*\n\n- one\n- two\n\n1. a\n\n```ts\nconst a = 1;\n```");
    expect(out).toContain("<strong>bold</strong>");
    expect(out).toContain("<em>italic</em>");
    expect(out).toContain("<ul");
    expect(out).toContain("<ol");
    expect(out).toContain("<pre");
    expect(out).toContain("Copy");
  });

  it("copes with a huge answer", () => {
    const started = performance.now();
    const out = html("word **bold** ".repeat(20_000));
    expect(performance.now() - started).toBeLessThan(2000);
    expect(out).toContain("longer than can be shown");
  });
});
