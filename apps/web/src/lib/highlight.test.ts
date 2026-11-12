import { describe, expect, it } from "vitest";
import { highlightLine, tokensOfHtml } from "./highlight.ts";

describe("code highlighting", () => {
  it("turns highlight.js output into text tokens with hljs classes only", () => {
    const tokens = highlightLine('import _ from "lodash";', "javascript");
    expect(tokens.map((t) => t.text).join("")).toBe('import _ from "lodash";');
    expect(tokens).toContainEqual({ text: "import", classes: "hljs-keyword" });
    expect(tokens).toContainEqual({ text: '"lodash"', classes: "hljs-string" });
  });

  it("keeps hostile content as text: tags, entities and attributes never become markup", () => {
    const line = '<img src=x onerror=alert(1)> "</span><script>x</script>" &amp;  ';
    for (const language of ["javascript", "xml", "json", null]) {
      const tokens = highlightLine(line, language);
      expect(tokens.map((t) => t.text).join(""), String(language)).toBe(line);
      for (const t of tokens) expect(t.classes).toMatch(/^(hljs-[a-z_]+( hljs-[a-z_]+)*)?$/);
    }
  });

  it("reads only highlight.js' own spans and escapes", () => {
    expect(
      tokensOfHtml(
        '<span class="hljs-title function_">f</span><b onclick="x">&lt;i&gt;</b><span class="evil">y</span>',
      ),
    ).toEqual([
      { text: "f", classes: "hljs-title" },
      { text: '<b onclick="x"><i></b>y', classes: "" },
    ]);
  });

  it("leaves unknown languages plain", () => {
    expect(highlightLine("x = 1", "cobol")).toEqual([{ text: "x = 1", classes: "" }]);
  });
});
