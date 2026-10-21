import { describe, expect, it } from "vitest";
import { de } from "./de.ts";
import { en } from "./en.ts";
import { resolveLanguage } from "./index.ts";

function keys(obj: object, prefix = ""): string[] {
  return Object.entries(obj).flatMap(([k, v]) =>
    typeof v === "string" ? [`${prefix}${k}`] : keys(v as object, `${prefix}${k}.`),
  );
}

/** ICU arguments like `{name}` or `{count, plural, ...}`; plural branch texts such as `{All scanned}` are not arguments. */
function placeholders(text: string): string[] {
  return [...text.matchAll(/\{(\w+)[,}]/g)].map((m) => m[1] ?? "").sort();
}

describe("i18n", () => {
  it("German has exactly the English keys", () => {
    expect(keys(de).sort()).toEqual(keys(en).sort());
  });

  it("German keeps every placeholder of the English source", () => {
    const get = (obj: object, path: string) =>
      path.split(".").reduce<unknown>((o, k) => (o as Record<string, unknown>)[k], obj) as string;
    for (const key of keys(en)) expect(placeholders(get(de, key)), key).toEqual(placeholders(get(en, key)));
  });

  it("no translation is empty", () => {
    const get = (obj: object, path: string) =>
      path.split(".").reduce<unknown>((o, k) => (o as Record<string, unknown>)[k], obj) as string;
    for (const key of keys(en)) expect(get(de, key).trim(), key).not.toBe("");
  });

  it("uses English unless the user explicitly chose a supported language", () => {
    expect(resolveLanguage(null)).toBe("en");
    expect(resolveLanguage(undefined)).toBe("en");
    expect(resolveLanguage("de")).toBe("de");
    expect(resolveLanguage("de-DE")).toBe("en");
    expect(resolveLanguage("fr")).toBe("en");
  });
});
