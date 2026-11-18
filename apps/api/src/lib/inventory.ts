/**
 * Writing inventory systems (ADR 0053), shared by the app's routes and the token API: a system with its software list in one
 * transaction, within the organisation's limits.
 */
import { newId } from "@garnetops/core";
import { INVENTORY_LIMITS, type InventoryReport, type InventorySystemInput } from "@garnetops/core/inventory";
import { schema } from "@garnetops/db";
import { and, count, eq } from "drizzle-orm";
import { db } from "../db.ts";
import { ProblemError } from "./problem.ts";

const s = schema.inventorySystem;
const sw = schema.inventorySoftware;
type Tx = Parameters<Parameters<typeof db.transaction>[0]>[0];

async function replaceSoftware(
  tx: Tx,
  organizationId: string,
  systemId: string,
  software: { name: string; version: string }[],
) {
  // A nightly report mostly says what the last one said: then nothing is rewritten.
  const stored = await tx
    .select({ name: sw.name, version: sw.version })
    .from(sw)
    .where(eq(sw.systemId, systemId));
  const lineOf = (item: { name: string; version: string }) => `${item.name}\u0000${item.version}`;
  const before = new Set(stored.map(lineOf));
  if (before.size === software.length && software.every((item) => before.has(lineOf(item)))) return;
  await tx.delete(sw).where(eq(sw.systemId, systemId));
  for (let i = 0; i < software.length; i += 500) {
    await tx
      .insert(sw)
      .values(software.slice(i, i + 500).map((item) => ({ systemId, organizationId, ...item })));
  }
}

async function requireRoom(tx: Tx, organizationId: string) {
  const [row] = await tx.select({ n: count() }).from(s).where(eq(s.organizationId, organizationId));
  if ((row?.n ?? 0) >= INVENTORY_LIMITS.systems) {
    throw new ProblemError(
      409,
      "inventory-full",
      `The inventory holds at most ${INVENTORY_LIMITS.systems} systems`,
    );
  }
}

/** A new system from the app. 409 when the key is taken. */
export async function createSystem(organizationId: string, userId: string, input: InventorySystemInput) {
  return db.transaction(async (tx) => {
    await requireRoom(tx, organizationId);
    const id = newId("inv");
    const { software, ...fields } = input;
    const inserted = await tx
      .insert(s)
      .values({ id, organizationId, ...fields, source: "manual", createdBy: userId })
      .onConflictDoNothing({ target: [s.organizationId, s.key] })
      .returning({ id: s.id });
    if (inserted.length === 0) {
      throw new ProblemError(409, "inventory-key-taken", "Another system already has this key");
    }
    await replaceSoftware(tx, organizationId, id, software);
    return id;
  });
}

/** Every field of a system as the app saves it. Null when the system is gone; 409 when the new key is taken. */
export async function updateSystem(organizationId: string, id: string, input: InventorySystemInput) {
  return db.transaction(async (tx) => {
    const [other] = await tx
      .select({ id: s.id })
      .from(s)
      .where(and(eq(s.organizationId, organizationId), eq(s.key, input.key)))
      .limit(1);
    if (other && other.id !== id) {
      throw new ProblemError(409, "inventory-key-taken", "Another system already has this key");
    }
    const { software, ...fields } = input;
    const updated = await tx
      .update(s)
      .set({ ...fields, source: "manual", updatedAt: new Date() })
      .where(and(eq(s.organizationId, organizationId), eq(s.id, id)))
      .returning({ id: s.id });
    if (updated.length === 0) return null;
    await replaceSoftware(tx, organizationId, id, software);
    return id;
  });
}

/**
 * A script's report of the system with this key: created when new, else the software replaced and the sent fields set.
 * Returns whether it was created.
 */
export async function reportSystem(
  organizationId: string,
  tokenId: string,
  key: string,
  report: InventoryReport,
  now = new Date(),
): Promise<{ id: string; created: boolean }> {
  return db.transaction(async (tx) => {
    const [existing] = await tx
      .select({ id: s.id })
      .from(s)
      .where(and(eq(s.organizationId, organizationId), eq(s.key, key)))
      .limit(1);
    const { software, ...fields } = report;
    const sent = Object.fromEntries(Object.entries(fields).filter(([, value]) => value !== undefined));
    const stamp = { source: "script" as const, reportedAt: now, reportedByToken: tokenId, updatedAt: now };
    if (existing) {
      await tx
        .update(s)
        .set({ ...sent, ...stamp })
        .where(eq(s.id, existing.id));
      await replaceSoftware(tx, organizationId, existing.id, software);
      return { id: existing.id, created: false };
    }
    await requireRoom(tx, organizationId);
    const id = newId("inv");
    await tx.insert(s).values({ id, organizationId, key, name: key, ...sent, ...stamp });
    await replaceSoftware(tx, organizationId, id, software);
    return { id, created: true };
  });
}
