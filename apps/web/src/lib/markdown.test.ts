import { describe, expect, it } from "vitest";
import {
  type Block,
  type Inline,
  MARKDOWN_LIMITS,
  parseInline,
  parseMarkdown,
  safeLink,
} from "./markdown.ts";

/** Every piece of text in a tree, to check that markup ends up as text and nowhere else. */
function textOf(nodes: Inline[]): string {
  return nodes.map((n) => (n.t === "text" || n.t === "code" ? n.v : textOf(n.c))).join("");
}
function kinds(nodes: Inline[]): string[] {
  return nodes.flatMap((n) => (n.t === "text" || n.t === "code" ? [n.t] : [n.t, ...kinds(n.c)]));
}
const blocks = (s: string) => parseMarkdown(s).blocks;
const first = (s: string): Block => blocks(s)[0] as Block;

describe("inline", () => {
  it("reads code, bold and italic, also nested", () => {
    expect(parseInline("a `b` c")).toEqual([
      { t: "text", v: "a " },
      { t: "code", v: "b" },
      { t: "text", v: " c" },
    ]);
    expect(kinds(parseInline("**bold *and italic* text** and _more_"))).toEqual([
      "strong",
      "text",
      "em",
      "text",
      "text",
      "text",
      "em",
      "text",
    ]);
    expect(textOf(parseInline("**bold *and italic* text**"))).toBe("bold and italic text");
  });

  it("does not turn snake_case, multiplication or stray stars into emphasis", () => {
    expect(parseInline("use my_var_name here")).toEqual([{ t: "text", v: "use my_var_name here" }]);
    expect(parseInline("2 * 3 * 4")).toEqual([{ t: "text", v: "2 * 3 * 4" }]);
    expect(parseInline("**unclosed and *also")).toEqual([{ t: "text", v: "**unclosed and *also" }]);
  });

  it("keeps markup characters inside code as they are", () => {
    expect(parseInline("`<script>alert(1)</script> **x**`")).toEqual([
      { t: "code", v: "<script>alert(1)</script> **x**" },
    ]);
    expect(parseInline("`` a ` b ``")).toEqual([{ t: "code", v: "a ` b" }]);
  });

  it("honours backslash escapes", () => {
    expect(textOf(parseInline("\\*not bold\\* and \\[x\\](y)"))).toBe("*not bold* and [x](y)");
  });

  it("shows raw HTML and entities as text, never as markup", () => {
    const html =
      '<script>alert(1)</script><img src=x onerror=alert(1)> &lt;b&gt; &amp; <a href="javascript:alert(1)">x</a>';
    const nodes = parseInline(html);
    expect(kinds(nodes)).toEqual(["text"]);
    expect(textOf(nodes)).toBe(html);
  });

  describe("links", () => {
    it("keeps http and https links and names the host", () => {
      expect(parseInline("[the advisory](https://advisories.example.com/CVE-2099-0001)")).toEqual([
        {
          t: "link",
          href: "https://advisories.example.com/CVE-2099-0001",
          host: "advisories.example.com",
          c: [{ t: "text", v: "the advisory" }],
        },
      ]);
      expect(parseInline("[x](http://example.lan:8080/a?b=c#d)")[0]).toMatchObject({
        t: "link",
        host: "example.lan:8080",
      });
    });

    it("shows other schemes as text with their address, so nothing is hidden", () => {
      for (const target of [
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "data:text/html;base64,PHNjcmlwdD4=",
        "vbscript:x",
        "file:///etc/passwd",
        "//evil.example.com",
        "/relative",
        "mailto:a@example.com",
        " javascript:alert(1)",
      ]) {
        const nodes = parseInline(`[click me](${target})`);
        expect(kinds(nodes), target).not.toContain("link");
        expect(textOf(nodes), target).toContain("click me");
        expect(textOf(nodes), target).toContain(target.trim());
      }
    });

    it("refuses credentials in the address, and nested or image links", () => {
      expect(kinds(parseInline("[x](https://user:pw@example.com/)"))).not.toContain("link");
      // Links never nest: whatever the reader sees as a link has plain content.
      const nested = parseInline("[a [inner](https://a.example.com) b](https://b.example.com)");
      for (const n of nested) if (n.t === "link") expect(kinds(n.c)).not.toContain("link");
      expect(kinds(parseInline("![alt](https://example.com/x.png)"))).toEqual(["text", "text"]);
      expect(textOf(parseInline("![alt](https://example.com/x.png)"))).toBe(
        "alt (https://example.com/x.png)",
      );
    });

    it("ignores a title after the address", () => {
      expect(parseInline('[x](https://example.com/a "title")')[0]).toMatchObject({
        t: "link",
        href: "https://example.com/a",
      });
    });

    it("recognises safe links only", () => {
      expect(safeLink("https://example.com/x")).toEqual({
        href: "https://example.com/x",
        host: "example.com",
      });
      expect(safeLink("javascript:alert(1)")).toBeNull();
      expect(safeLink("https://")).toBeNull();
      expect(safeLink("")).toBeNull();
    });
  });
});

describe("blocks", () => {
  it("reads paragraphs, headings and block quotes", () => {
    expect(blocks("First line\nsecond line\n\nNext")).toMatchObject([{ t: "p" }, { t: "p" }]);
    expect(first("## Title ##")).toMatchObject({ t: "heading", level: 2 });
    expect(first("###### Deep")).toMatchObject({ t: "heading", level: 3 });
    expect(textOf((first("# Title #") as Extract<Block, { t: "heading" }>).c)).toBe("Title");
    expect(first("> quoted\n> text")).toMatchObject({ t: "quote" });
  });

  it("reads bullet, numbered and nested lists", () => {
    const list = first("- one\n- two\n  - nested\n- three") as Extract<Block, { t: "list" }>;
    expect(list.ordered).toBe(false);
    expect(list.items).toHaveLength(3);
    expect(list.items[1]?.sub?.items).toHaveLength(1);
    expect(first("1. a\n2. b")).toMatchObject({ t: "list", ordered: true });
    expect(blocks("- a\n\ntext\n\n1. b")).toMatchObject([
      { t: "list" },
      { t: "p" },
      { t: "list", ordered: true },
    ]);
  });

  it("reads fenced code, also an unclosed one while the answer is still arriving", () => {
    expect(first("```ts\nconst a = 1;\n```")).toEqual({ t: "code", lang: "ts", v: "const a = 1;" });
    expect(first("```\nfirst\n\nsecond")).toEqual({ t: "code", lang: "", v: "first\n\nsecond" });
    expect(blocks("~~~\n```\n~~~")).toEqual([{ t: "code", lang: "", v: "```" }]);
  });

  it("never interprets markup inside a code block", () => {
    const block = first("```html\n<script>alert(1)</script>\n[x](javascript:alert(1))\n```") as Extract<
      Block,
      { t: "code" }
    >;
    expect(block.v).toBe("<script>alert(1)</script>\n[x](javascript:alert(1))");
  });

  it("does not make a language label out of anything odd", () => {
    expect(first("```<script>\nx\n```")).toMatchObject({ t: "p" });
  });
});

describe("hostile and huge input", () => {
  it("cuts input beyond the limit and says so", () => {
    const result = parseMarkdown("a".repeat(MARKDOWN_LIMITS.chars * 3));
    expect(result.truncated).toBe(true);
    expect(textOf((result.blocks[0] as Extract<Block, { t: "p" }>).c).length).toBe(MARKDOWN_LIMITS.chars);
  });

  it("caps the number of blocks", () => {
    const result = parseMarkdown(Array.from({ length: 5000 }, (_, i) => `para ${i}`).join("\n\n"));
    expect(result.blocks.length).toBeLessThanOrEqual(MARKDOWN_LIMITS.blocks);
    expect(result.truncated).toBe(true);
  });

  it("stays fast on input built to make a parser slow", () => {
    const started = performance.now();
    const attacks = [
      "**a ".repeat(15_000),
      "*a ".repeat(20_000),
      "_a ".repeat(20_000),
      "[a](".repeat(15_000),
      "[".repeat(50_000),
      "`".repeat(50_000),
      "` a ".repeat(15_000),
      "**".repeat(30_000),
      "*".repeat(59_000),
      "*a*".repeat(15_000),
      `${"*".repeat(30)}x${"*".repeat(30)}`.repeat(1000),
      "- ".repeat(30_000),
      `${"  ".repeat(500)}- x\n`.repeat(100),
      `# ${" ".repeat(50_000)}x`,
      "> ".repeat(30_000),
      "```\n".repeat(10_000),
      "\\".repeat(59_000),
      `${"[a](https://example.com) ".repeat(2000)}`,
    ];
    for (const attack of attacks) parseMarkdown(attack);
    expect(performance.now() - started).toBeLessThan(3000);
  });

  it("limits nesting", () => {
    const deep = `${"*a ".repeat(50)}x${" a*".repeat(50)}`;
    const depth = (nodes: Inline[]): number =>
      Math.max(0, ...nodes.map((n) => (n.t === "text" || n.t === "code" ? 0 : 1 + depth(n.c))));
    expect(depth(parseInline(deep))).toBeLessThanOrEqual(MARKDOWN_LIMITS.depth + 1);
    const lists = parseMarkdown(
      Array.from({ length: 300 }, (_, i) => `${" ".repeat(i % 8)}- item ${i}`).join("\n"),
    );
    expect(JSON.stringify(lists.blocks).match(/"sub"/g)?.length ?? 0).toBeLessThan(300);
  });
});
