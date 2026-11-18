/**
 * The inventory (ADR 0053): systems and their software as a person or a script tells them. Pure: the shapes both the app and the
 * token API accept, with their limits. Everything here is text somebody typed or a script sent; it is cleaned and cut, never
 * interpreted, and never matched against the vulnerability database.
 */
import { z } from "zod";

export const INVENTORY_KINDS = [
  "server",
  "vm",
  "container",
  "website",
  "network",
  "appliance",
  "workstation",
  "other",
] as const;
export type InventoryKind = (typeof INVENTORY_KINDS)[number];

export const INVENTORY_LIMITS = {
  systems: 5000,
  /** Pieces of software on one system: a server with a desktop has a few thousand packages. */
  software: 5000,
  key: 120,
  name: 120,
  environment: 60,
  notes: 2000,
  tags: 20,
  tag: 40,
  softwareName: 120,
  softwareVersion: 80,
  /** Bytes of one request of a script. */
  body: 1024 * 1024,
} as const;

export const INVENTORY_TOKEN_SCOPES = ["write", "read"] as const;
export type InventoryTokenScope = (typeof INVENTORY_TOKEN_SCOPES)[number];

/** One line of text: control and bidirectional characters removed, spaces collapsed, cut to `max`. */
export function cleanInventoryText(value: string, max: number): string {
  return (
    value
      // biome-ignore lint/suspicious/noControlCharactersInRegex: removing control characters is the point
      .replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, max)
  );
}

/** Notes may have line breaks; everything else is cleaned as one line would be. */
function cleanNotes(value: string): string {
  return value
    .split(/\r?\n/)
    .map((line) => cleanInventoryText(line, INVENTORY_LIMITS.notes))
    .join("\n")
    .trim()
    .slice(0, INVENTORY_LIMITS.notes);
}

const line = (max: number) =>
  z
    .string()
    .max(max * 4)
    .transform((v) => cleanInventoryText(v, max));
const optionalLine = (max: number) =>
  z
    .string()
    .max(max * 4)
    .nullish()
    .transform((v) => (v ? cleanInventoryText(v, max) || null : null));

/** The stable name a script addresses a system by: letters, digits, dot, dash, underscore, colon. */
export const inventoryKeySchema = z
  .string()
  .regex(
    /^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/,
    "Letters, digits, dot, dash, underscore and colon, at most 120",
  );

/** A key from a name, for systems added by hand: "Web Server 1" becomes "web-server-1". Empty when nothing is left. */
export function inventoryKeyOf(name: string): string {
  return name
    .normalize("NFKD")
    .replace(/[^A-Za-z0-9._:-]+/g, "-")
    .replace(/^[^A-Za-z0-9]+|-+$/g, "")
    .toLowerCase()
    .slice(0, INVENTORY_LIMITS.key);
}

const softwareItem = z.object({
  name: line(INVENTORY_LIMITS.softwareName).refine((v) => v.length > 0, "A name is needed"),
  version: z
    .string()
    .max(INVENTORY_LIMITS.softwareVersion * 4)
    .nullish()
    .transform((v) => cleanInventoryText(v ?? "", INVENTORY_LIMITS.softwareVersion)),
});
export type InventorySoftware = z.infer<typeof softwareItem>;

/** The software list: each name and version once, sorted, so the same list sent twice is the same list. */
export const inventorySoftwareSchema = z
  .array(softwareItem)
  .max(INVENTORY_LIMITS.software)
  .transform((items) => {
    const seen = new Map<string, InventorySoftware>();
    for (const item of items) seen.set(`${item.name}\u0000${item.version}`, item);
    return [...seen.values()].sort(
      (a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version),
    );
  });

const tags = z
  .array(z.string().max(INVENTORY_LIMITS.tag * 4))
  .max(INVENTORY_LIMITS.tags * 4)
  .transform((all) =>
    [...new Set(all.map((t) => cleanInventoryText(t, INVENTORY_LIMITS.tag)).filter(Boolean))].slice(
      0,
      INVENTORY_LIMITS.tags,
    ),
  );
const notes = z
  .string()
  .max(INVENTORY_LIMITS.notes * 4)
  .nullish()
  .transform((v) => (v ? cleanNotes(v) || null : null));

/** A system as the app saves it: every field is set. */
export const inventorySystemSchema = z.object({
  key: inventoryKeySchema,
  name: line(INVENTORY_LIMITS.name).refine((v) => v.length > 0, "A name is needed"),
  kind: z.enum(INVENTORY_KINDS).default("server"),
  environment: optionalLine(INVENTORY_LIMITS.environment),
  notes,
  tags: tags.default([]),
  software: inventorySoftwareSchema.default([]),
});
export type InventorySystemInput = z.infer<typeof inventorySystemSchema>;

/**
 * A system as a script reports it: the software list always (it replaces the stored one), every other field only when sent, so
 * what a person keeps by hand (notes, tags) survives the next report.
 */
export const inventoryReportSchema = z.object({
  name: line(INVENTORY_LIMITS.name)
    .refine((v) => v.length > 0, "A name is needed")
    .optional(),
  kind: z.enum(INVENTORY_KINDS).optional(),
  environment: optionalLine(INVENTORY_LIMITS.environment).optional(),
  notes: notes.optional(),
  tags: tags.optional(),
  software: inventorySoftwareSchema,
});
export type InventoryReport = z.infer<typeof inventoryReportSchema>;

/**
 * The software list as typed in the app: one per line, the name and then the version ("nginx 1.26.0"); the last word is the
 * version when the line has more than one word. Empty lines are skipped.
 */
export function parseSoftwareLines(text: string): { name: string; version: string }[] {
  const out: { name: string; version: string }[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const row = cleanInventoryText(raw, INVENTORY_LIMITS.softwareName + INVENTORY_LIMITS.softwareVersion + 1);
    if (!row) continue;
    const at = row.lastIndexOf(" ");
    out.push(at > 0 ? { name: row.slice(0, at), version: row.slice(at + 1) } : { name: row, version: "" });
  }
  return out;
}

/** The software list as lines to edit, the reverse of `parseSoftwareLines`. */
export const softwareLines = (items: readonly { name: string; version: string }[]): string =>
  items.map((i) => (i.version ? `${i.name} ${i.version}` : i.name)).join("\n");
