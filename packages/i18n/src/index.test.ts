import { describe, expect, it } from "vitest";
import { de } from "./de.ts";
import { en } from "./en.ts";
import { renderNotificationItem, resolveLanguage } from "./index.ts";

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

describe("renderNotificationItem", () => {
  it("writes the notification in the reader's language, with the facts filled in", () => {
    expect(renderNotificationItem("en", "gateBlocked", { repository: "billing", rules: 2 })).toEqual({
      title: "Quality gate blocked: billing",
      text: "Rules set to Block that matched: 2.",
    });
    expect(renderNotificationItem("de", "gateBlocked", { repository: "billing", rules: 2 }).title).toBe(
      "Quality Gate blockiert: billing",
    );
  });

  it("translates a role parameter and ignores unknown roles", () => {
    expect(renderNotificationItem("en", "roleChanged", { role: "admin" }).text).toBe("You are now an admin.");
    expect(renderNotificationItem("de", "roleChanged", { role: "viewer" }).text).toBe(
      "Sie sind jetzt Betrachter.",
    );
    expect(renderNotificationItem("en", "roleChanged", { role: "toString" }).text).toBe(
      "You are now toString.",
    );
  });

  it("falls back for a key it does not know, and never expands text inside a value", () => {
    expect(renderNotificationItem("en", "somethingNew", {}).title).toBe("Notification");
    expect(renderNotificationItem("en", "constructor", {}).title).toBe("Notification");
    const tricky = renderNotificationItem("en", "scanFailed", { repository: "{rules} <b>x</b>" });
    expect(tricky.title).toBe("Scan failed: {rules} <b>x</b>");
  });
});
