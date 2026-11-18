import { describe, expect, it } from "vitest";
import {
  cleanInventoryText,
  INVENTORY_LIMITS,
  inventoryKeyOf,
  inventoryKeySchema,
  inventoryReportSchema,
  inventorySystemSchema,
  parseSoftwareLines,
  softwareLines,
} from "./inventory.ts";

describe("inventory input (ADR 0053)", () => {
  it("keeps typed and reported text as one clean line", () => {
    expect(cleanInventoryText("  web\r\n‮1\u0000  ", 20)).toBe("web 1");
    expect(cleanInventoryText("x".repeat(50), 10)).toHaveLength(10);
  });

  it("accepts keys a script can put in a URL, and makes one from a name", () => {
    for (const key of ["web-1", "db01.example.lan", "rack:3_a"])
      expect(inventoryKeySchema.safeParse(key).success).toBe(true);
    for (const key of ["", "-web", "a b", "../x", "ä", "a".repeat(121)])
      expect(inventoryKeySchema.safeParse(key).success).toBe(false);
    expect(inventoryKeyOf("Web Server 1 (Berlin)")).toBe("web-server-1-berlin");
    expect(inventoryKeyOf("  ...  ")).toBe("");
  });

  it("stores each software name and version once, sorted, cleaned and limited", () => {
    const system = inventorySystemSchema.parse({
      key: "web-1",
      name: "  Web 1 ",
      notes: "line one\r\n line\u0007 two ",
      tags: ["prod", "prod", " ", "dmz"],
      software: [
        { name: "php", version: "8.3.12" },
        { name: "nginx", version: "1.26.0" },
        { name: "php", version: "8.3.12" },
        { name: "php", version: "8.2.24" },
        { name: "openssl" },
      ],
    });
    expect(system).toMatchObject({
      name: "Web 1",
      kind: "server",
      environment: null,
      notes: "line one\nline two",
      tags: ["prod", "dmz"],
    });
    expect(system.software).toEqual([
      { name: "nginx", version: "1.26.0" },
      { name: "openssl", version: "" },
      { name: "php", version: "8.2.24" },
      { name: "php", version: "8.3.12" },
    ]);
    expect(inventorySystemSchema.safeParse({ key: "x", name: " " }).success).toBe(false);
    expect(inventorySystemSchema.safeParse({ key: "x", name: "x", kind: "spaceship" }).success).toBe(false);
    const many = Array.from({ length: INVENTORY_LIMITS.software + 1 }, (_, i) => ({
      name: `p${i}`,
      version: "1",
    }));
    expect(inventorySystemSchema.safeParse({ key: "x", name: "x", software: many }).success).toBe(false);
  });

  it("a report replaces the software and leaves alone what it does not send", () => {
    const report = inventoryReportSchema.parse({ software: [{ name: "nginx", version: "1.26.0" }] });
    expect(Object.keys(report)).toEqual(["software"]);
    expect(inventoryReportSchema.parse({ software: [], notes: null })).toEqual({ software: [], notes: null });
    expect(inventoryReportSchema.safeParse({ name: "x" }).success).toBe(false);
  });

  it("reads the software list as lines: the last word is the version", () => {
    const lines = "nginx 1.26.0\n\n  PHP FPM   8.3.12 \nopenssl\n";
    expect(parseSoftwareLines(lines)).toEqual([
      { name: "nginx", version: "1.26.0" },
      { name: "PHP FPM", version: "8.3.12" },
      { name: "openssl", version: "" },
    ]);
    expect(softwareLines(parseSoftwareLines(lines))).toBe("nginx 1.26.0\nPHP FPM 8.3.12\nopenssl");
  });
});
