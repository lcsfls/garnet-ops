import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const css = readFileSync(new URL("../styles.css", import.meta.url), "utf8");

/** The declarations of the first rule that starts with `selector {`, normalised. */
function declarations(selector: string): string[] {
  const start = css.indexOf(`${selector} {`);
  if (start < 0) throw new Error(`missing rule: ${selector}`);
  const body = css.slice(start + selector.length + 2, css.indexOf("}", start));
  return body
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split(";")
    .map((d) => d.trim())
    .filter(Boolean);
}

describe("theme tokens", () => {
  it("defines the dark theme identically for the system preference and the explicit choice", () => {
    const system = declarations(':root:not([data-theme="light"])');
    const chosen = declarations(':root[data-theme="dark"]');
    expect(system.length).toBeGreaterThan(20);
    expect(chosen).toEqual(system);
  });

  it("overrides every colour token of the light theme in the dark theme", () => {
    const names = (decls: string[]) =>
      decls.map((d) => d.split(":")[0] ?? "").filter((n) => n.startsWith("--"));
    const light = names(declarations(":root")).filter((n) => n !== "--radius");
    const dark = new Set(names(declarations(':root[data-theme="dark"]')));
    expect(light.filter((n) => !dark.has(n))).toEqual([]);
  });
});
