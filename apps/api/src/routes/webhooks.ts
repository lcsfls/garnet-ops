/**
 * Scan on push (ADR 0045). Two parts:
 *
 * - `webhookRoutes` under `/repositories/:id/webhook`, signed in: owners and admins, or the owner of a private repository, switch
 *   it on (a new address and secret, shown once, with a recent sign-in), see the last deliveries, and switch it off.
 * - `webhookDeliveryRoutes` under `/api/v1/hooks/:pathId`, without a session: the forge's delivery. Nothing of it is read before
 *   its HMAC-SHA256 matches; then only the event and the pushed ref count. A push to the scanned branch queues a scan unless one
 *   is already queued or running. Answers are codes only, so the forge's delivery log shows what happened.
 */
import { newId } from "@garnetops/core";
import {
  MAX_WEBHOOK_BODY_BYTES,
  signatureMatches,
  type WebhookResult,
  webhookHeaders,
  webhookIntent,
} from "@garnetops/core/webhook";
import { repositoryVisibleTo, schema } from "@garnetops/db";
import { and, eq, inArray, sql } from "drizzle-orm";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { db } from "../db.ts";
import { env } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, isAdmin, requireRole } from "../lib/context.ts";
import { clientIp } from "../lib/ip.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { queueScan } from "../lib/scan-queue.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";
import { newWebhookSecret, openWebhookSecret, sealWebhookSecret } from "../lib/webhook-secret.ts";

const w = schema.repositoryWebhook;
const KEEP_DELIVERIES = 10;
/** Deliveries per webhook and minute, and per address and minute; a busy repository pushes far less. */
const PER_HOOK_PER_MINUTE = 60;
const PER_IP_PER_MINUTE = 120;

const hookUrl = (pathId: string) => `${env.PUBLIC_URL.replace(/\/+$/, "")}/api/v1/hooks/${pathId}`;

type Actor = AppEnv["Variables"]["actor"];

/** The repository, if the actor sees it and may change its webhook: admins, or the owner of a private repository. */
async function manageable(actor: Actor, id: string) {
  const [repo] = await db
    .select({
      id: schema.repository.id,
      visibility: schema.repository.visibility,
      ownerUserId: schema.repository.ownerUserId,
    })
    .from(schema.repository)
    .where(and(eq(schema.repository.id, id), repositoryVisibleTo(actor)))
    .limit(1);
  if (!repo) throw notFound("Repository");
  const own = repo.visibility === "private" && repo.ownerUserId === actor.userId;
  return { repo, canManage: own || isAdmin(actor) };
}

export const webhookRoutes = new Hono<AppEnv>()
  /** Whether the webhook is on, its address (for those who may change it) and its last deliveries. Never the secret. */
  .get("/", async (c) => {
    const actor = c.get("actor");
    const { repo, canManage } = await manageable(actor, c.req.param("id") as string);
    const [row] = await db.select().from(w).where(eq(w.repositoryId, repo.id)).limit(1);
    return c.json({
      enabled: Boolean(row),
      canManage,
      url: row && canManage ? hookUrl(row.pathId) : null,
      createdAt: row?.createdAt.toISOString() ?? null,
      lastDeliveryAt: row?.lastDeliveryAt?.toISOString() ?? null,
      deliveries: row?.deliveries ?? [],
    });
  })
  /** Switches it on, or replaces address and secret. Both are shown once in the answer and never again. */
  .post("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const { repo, canManage } = await manageable(actor, c.req.param("id") as string);
    if (!canManage)
      throw new ProblemError(
        403,
        "forbidden",
        "Only owners and admins, or the owner of a private repository",
      );
    requireRecentSignIn(actor);
    const id = newId("hook");
    const pathId = newWebhookSecret();
    const secret = newWebhookSecret();
    const replaced = await db.transaction(async (tx) => {
      const deleted = await tx.delete(w).where(eq(w.repositoryId, repo.id)).returning({ id: w.id });
      await tx.insert(w).values({
        id,
        organizationId: actor.organizationId,
        repositoryId: repo.id,
        pathId,
        secretSealed: sealWebhookSecret(secret, id),
        createdBy: actor.userId,
      });
      return deleted.length > 0;
    });
    await audit(actor, replaced ? "repository.webhook_replaced" : "repository.webhook_created", {
      type: "repository",
      id: repo.id,
    });
    c.header("cache-control", "no-store");
    return c.json({ url: hookUrl(pathId), secret }, 201);
  })
  .delete("/", async (c) => {
    const actor = c.get("actor");
    const { repo, canManage } = await manageable(actor, c.req.param("id") as string);
    if (!canManage)
      throw new ProblemError(
        403,
        "forbidden",
        "Only owners and admins, or the owner of a private repository",
      );
    const deleted = await db.delete(w).where(eq(w.repositoryId, repo.id)).returning({ id: w.id });
    if (deleted.length > 0)
      await audit(actor, "repository.webhook_removed", { type: "repository", id: repo.id });
    return c.body(null, 204);
  });

/** Adds one delivery to the webhook's short list, newest first. */
async function remember(webhookId: string, event: string | null, result: WebhookResult) {
  const entry = { at: new Date().toISOString(), event: event ?? "unknown", result };
  await db
    .update(w)
    .set({
      lastDeliveryAt: new Date(),
      deliveries: sql`(jsonb_build_array(${JSON.stringify(entry)}::jsonb) || ${w.deliveries}) - ${KEEP_DELIVERIES}`,
    })
    .where(eq(w.id, webhookId));
}

const answer = (result: WebhookResult) => ({ result });

export const webhookDeliveryRoutes = new Hono().post(
  "/:pathId",
  bodyLimit({
    maxSize: MAX_WEBHOOK_BODY_BYTES,
    onError: (c) => c.json(answer("unreadable"), 413),
  }),
  async (c) => {
    const pathId = c.req.param("pathId");
    const ip = clientIp(c.req.raw.headers) ?? "unknown";
    if (!/^[A-Za-z0-9_-]{43}$/.test(pathId)) return c.json({ error: "not_found" }, 404);
    try {
      await rateLimit(`hook-ip:${ip}`, PER_IP_PER_MINUTE);
      await rateLimit(`hook:${pathId}`, PER_HOOK_PER_MINUTE);
    } catch {
      return c.json(answer("rate-limited"), 429);
    }
    const [hook] = await db
      .select({
        id: w.id,
        organizationId: w.organizationId,
        repositoryId: w.repositoryId,
        secretSealed: w.secretSealed,
        branch: schema.repository.branch,
        inactiveAt: schema.repository.inactiveAt,
      })
      .from(w)
      .innerJoin(schema.repository, eq(schema.repository.id, w.repositoryId))
      .where(eq(w.pathId, pathId))
      .limit(1);
    if (!hook) return c.json({ error: "not_found" }, 404);

    const body = new Uint8Array(await c.req.arrayBuffer());
    const { event, signature } = webhookHeaders((name) => c.req.header(name));
    const secret = openWebhookSecret(hook.secretSealed, hook.id);
    if (!secret || !signatureMatches(secret, body, signature)) {
      await remember(hook.id, event, "bad-signature");
      return c.json(answer("bad-signature"), 401);
    }

    let payload: unknown = null;
    try {
      payload = event === "push" ? JSON.parse(new TextDecoder().decode(body)) : null;
    } catch {
      payload = null;
    }
    const intent = webhookIntent(event, payload, hook.branch);
    let result: WebhookResult;
    if (intent !== "scan") {
      result = intent;
    } else if (hook.inactiveAt) {
      result = "inactive";
    } else {
      const [active] = await db
        .select({ id: schema.scan.id })
        .from(schema.scan)
        .where(
          and(
            eq(schema.scan.repositoryId, hook.repositoryId),
            inArray(schema.scan.state, ["queued", "running"]),
          ),
        )
        .limit(1);
      if (active) {
        result = "already-queued";
      } else {
        const scanId = await queueScan(hook.organizationId, hook.repositoryId, null, "webhook");
        await audit(
          { organizationId: hook.organizationId, userId: null, ip },
          "scan.requested",
          { type: "repository", id: hook.repositoryId },
          { scanId, via: "webhook" },
        );
        result = "scan-queued";
      }
    }
    await remember(hook.id, event, result);
    return c.json(answer(result), result === "scan-queued" ? 202 : 200);
  },
);
