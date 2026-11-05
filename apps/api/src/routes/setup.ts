import { randomBytes, timingSafeEqual } from "node:crypto";
import { newId } from "@garnetops/core";
import { BACKUP_PASSPHRASE_MAX } from "@garnetops/core/backup";
import { isTimeZone, schema } from "@garnetops/db";
import { count, eq } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { auth } from "../auth.ts";
import { db, pool } from "../db.ts";
import { env, vaultPublicKey } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { clientIp } from "../lib/ip.ts";
import { ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { RestoreFailure, restoreBackup } from "../lib/restore.ts";

/**
 * First-run setup: creates the first organisation and its owner.
 *
 * Only possible while no user exists, and only with the one-time setup token
 * that the API prints to its log on start (or GARNETOPS_SETUP_TOKEN). This
 * stops whoever reaches a fresh installation first from claiming it.
 */
let setupToken: string | null = null;

export async function prepareSetupToken(): Promise<void> {
  if (!(await setupNeeded())) return;
  setupToken = process.env.GARNETOPS_SETUP_TOKEN || randomBytes(18).toString("base64url");
  console.log("────────────────────────────────────────────────────────────");
  console.log(" GarnetOps is not set up yet. Open the web app and enter");
  console.log(` this one-time setup token:  ${setupToken}`);
  console.log("────────────────────────────────────────────────────────────");
}

async function setupNeeded(): Promise<boolean> {
  const [row] = await db.select({ n: count() }).from(schema.user);
  return (row?.n ?? 0) === 0;
}

function tokenMatches(given: string): boolean {
  if (!setupToken) return false;
  const a = Buffer.from(given);
  const b = Buffer.from(setupToken);
  return a.length === b.length && timingSafeEqual(a, b);
}

const body = z.object({
  token: z.string().min(1).max(200),
  organizationName: z.string().trim().min(2).max(100),
  name: z.string().trim().min(1).max(100),
  email: z.string().trim().toLowerCase().email().max(254),
  password: z.string().min(12).max(256),
  /** The owner's IANA zone (from the browser); the nightly scan runs at 04:00 in it (ADR 0005). */
  timeZone: z.string().refine(isTimeZone, "Unknown time zone").optional(),
});

/**
 * A restore (ADR 0046) in two steps, so the passphrase never travels in a header or a URL and the file can stream: the first
 * request checks the setup token and keeps the passphrase in this process's memory for ten minutes; the second sends the file.
 */
const RESTORE_WINDOW_MS = 10 * 60_000;
const restores = new Map<string, { passphrase: string; expires: number }>();

function takeRestore(id: string) {
  const now = Date.now();
  for (const [key, value] of restores) if (value.expires < now) restores.delete(key);
  const entry = restores.get(id);
  restores.delete(id);
  return entry ?? null;
}

const restoreBody = z.object({
  token: z.string().min(1).max(200),
  passphrase: z.string().min(1).max(BACKUP_PASSPHRASE_MAX),
});

export const setupRoutes = new Hono()
  .get("/", async (c) => c.json({ needed: await setupNeeded() }))
  .post("/", async (c) => {
    const input = body.parse(await c.req.json());
    // A session-level advisory lock serialises concurrent setup attempts.
    const client = await pool.connect();
    try {
      await client.query("select pg_advisory_lock(hashtext('garnetops.setup'))");
      if (!(await setupNeeded()))
        throw new ProblemError(409, "already-set-up", "GarnetOps is already set up");
      if (!tokenMatches(input.token))
        throw new ProblemError(403, "invalid-setup-token", "The setup token is not valid");

      const ctx = await auth.$context;
      const user = await ctx.internalAdapter.createUser(
        { email: input.email, name: input.name, emailVerified: true },
        { method: "admin" },
      );
      const organizationId = newId("org");
      try {
        await ctx.internalAdapter.linkAccount({
          userId: user.id,
          providerId: "credential",
          accountId: user.id,
          password: await ctx.password.hash(input.password),
        });
        await db.transaction(async (tx) => {
          await tx.insert(schema.organization).values({
            id: organizationId,
            name: input.organizationName,
            ...(input.timeZone ? { scanTimeZone: input.timeZone } : {}),
          });
          await tx.insert(schema.membership).values({ organizationId, userId: user.id, role: "owner" });
        });
      } catch (error) {
        // Without this, a half-created owner would end setup for good: a user exists but cannot sign in to anything.
        await db.delete(schema.user).where(eq(schema.user.id, user.id));
        throw error;
      }
      await audit({ organizationId, userId: user.id, ip: null }, "setup.completed", {
        type: "organization",
        id: organizationId,
      });
      setupToken = null;
      return c.json({ ok: true }, 201);
    } finally {
      await client.query("select pg_advisory_unlock(hashtext('garnetops.setup'))").catch(() => {});
      client.release();
    }
  })
  /** Restoring instead of setting up: checks the setup token and keeps the passphrase for the upload that follows. */
  .post("/restore", async (c) => {
    const ip = clientIp(c.req.raw.headers) ?? "unknown";
    await rateLimit(`setup-restore:${ip}`, 10, 15 * 60_000);
    const input = restoreBody.parse(await c.req.json());
    if (!(await setupNeeded())) throw new ProblemError(409, "already-set-up", "GarnetOps is already set up");
    if (!tokenMatches(input.token)) {
      await audit({ organizationId: null, userId: null, ip }, "setup.restore_refused", undefined, {
        reason: "invalid-setup-token",
      });
      throw new ProblemError(403, "invalid-setup-token", "The setup token is not valid");
    }
    const id = randomBytes(18).toString("base64url");
    restores.set(id, { passphrase: input.passphrase, expires: Date.now() + RESTORE_WINDOW_MS });
    return c.json({ id }, 201);
  })
  /** The backup file itself, as the request body. Restores it in one transaction, or changes nothing. */
  .put("/restore/:id", async (c) => {
    const entry = takeRestore(c.req.param("id"));
    if (!entry) throw new ProblemError(404, "restore-expired", "Start the restore again");
    if (!(await setupNeeded())) throw new ProblemError(409, "already-set-up", "GarnetOps is already set up");
    const body = c.req.raw.body;
    if (!body) throw new ProblemError(400, "restore-not-a-backup", "No file was sent");
    try {
      const summary = await restoreBackup(body, entry.passphrase, {
        pool,
        vaultPublicKey,
        authKey: (await auth.$context).secretConfig,
        authSecret: env.BETTER_AUTH_SECRET,
      });
      setupToken = null;
      console.log(`restored a backup: ${summary.rows} rows in ${summary.tables} tables`);
      return c.json(summary, 201);
    } catch (error) {
      const code = error instanceof RestoreFailure ? error.code : "failed";
      throw new ProblemError(
        code === "not-empty" ? 409 : 422,
        `restore-${code}`,
        "The backup was not restored",
      );
    }
  });
