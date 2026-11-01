/**
 * Scan on push (ADR 0045). Two parts:
 *
 * - `webhookRoutes` under `/repositories/:id/webhook`, signed in: owners and admins, or the owner of a private repository, switch
 *   it on (a new address and secret, shown once, with a recent sign-in), see the last deliveries, and switch it off. With their
 *   own connected account on the forge they can let the worker register it there (lib/repository-webhook.ts).
 * - `webhookDeliveryRoutes` under `/api/v1/hooks/:pathId`, without a session: the forge's delivery. Nothing of it is read before
 *   its HMAC-SHA256 matches; then only the event and the pushed ref count. A push to the scanned branch queues a scan unless one
 *   is already queued or running. Answers are codes only, so the forge's delivery log shows what happened.
 */
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
import { z } from "zod";
import { db } from "../db.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, isAdmin, requireRole } from "../lib/context.ts";
import { clientIp } from "../lib/ip.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import {
  hookUrl,
  registerConnectionFor,
  requireRegisterConnection,
  switchOffWebhook,
  switchOnWebhook,
} from "../lib/repository-webhook.ts";
import { queueScan } from "../lib/scan-queue.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";
import { openWebhookSecret } from "../lib/webhook-secret.ts";

const w = schema.repositoryWebhook;
const KEEP_DELIVERIES = 10;
/** Deliveries per webhook and minute, and per address and minute; a busy repository pushes far less. */
const PER_HOOK_PER_MINUTE = 60;
const PER_IP_PER_MINUTE = 120;

/** `register: true`: create the webhook in the forge with the caller's own connected account (ADR 0045). */
const switchOnBody = z.object({ register: z.boolean().optional() });

type Actor = AppEnv["Variables"]["actor"];

/** The repository, if the actor sees it and may change its webhook: admins, or the owner of a private repository. */
async function manageable(actor: Actor, id: string) {
  const [repo] = await db
    .select({
      id: schema.repository.id,
      url: schema.repository.url,
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

const forbidden = () =>
  new ProblemError(403, "forbidden", "Only owners and admins, or the owner of a private repository");

/** The account a connection signs in as: its login, else the forge's host. */
const accountOf = (connection: { accountLogin: string | null; webBaseUrl: string }) =>
  connection.accountLogin ?? new URL(connection.webBaseUrl).host;

export const webhookRoutes = new Hono<AppEnv>()
  /**
   * Whether the webhook is on, its address (for those who may change it) and its last deliveries. Never the secret. For those
   * who may change it also: how it was registered in the forge (`registration`), and whether the caller could let GarnetOps
   * register it with their own connected account (`canRegister`).
   */
  .get("/", async (c) => {
    const actor = c.get("actor");
    const { repo, canManage } = await manageable(actor, c.req.param("id") as string);
    const [found] = await db
      .select({
        hook: w,
        login: schema.forgeConnection.accountLogin,
        webBaseUrl: schema.forgeConnection.webBaseUrl,
        kind: schema.forgeConnection.forgeKind,
      })
      .from(w)
      .leftJoin(schema.forgeConnection, eq(schema.forgeConnection.id, w.connectionId))
      .where(eq(w.repositoryId, repo.id))
      .limit(1);
    const row = found?.hook;
    let canRegister: { login: string; kind: string; problem: string | null } | null = null;
    if (canManage) {
      const own = await registerConnectionFor(actor, repo.url);
      if (own)
        canRegister = {
          login: accountOf(own.connection),
          kind: own.connection.forgeKind,
          problem: own.problem,
        };
    }
    return c.json({
      enabled: Boolean(row),
      canManage,
      url: row && canManage ? hookUrl(row.pathId) : null,
      createdAt: row?.createdAt.toISOString() ?? null,
      lastDeliveryAt: row?.lastDeliveryAt?.toISOString() ?? null,
      deliveries: row?.deliveries ?? [],
      registration:
        row?.registerState && canManage
          ? {
              state: row.registerState,
              reason: row.registerReason,
              connection:
                found?.webBaseUrl && found.kind
                  ? {
                      login: accountOf({ accountLogin: found.login, webBaseUrl: found.webBaseUrl }),
                      kind: found.kind,
                    }
                  : null,
            }
          : null,
      canRegister,
    });
  })
  /**
   * Switches it on, or replaces address and secret. Both are shown once in the answer and never again. With
   * `{ "register": true }` the worker also creates the webhook in the forge with the caller's own connected account.
   */
  .post("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const input = switchOnBody.parse(await c.req.json().catch(() => ({})));
    const { repo, canManage } = await manageable(actor, c.req.param("id") as string);
    if (!canManage) throw forbidden();
    requireRecentSignIn(actor);
    let connection = null;
    if (input.register) {
      // Only the caller's own connection is ever a candidate, for admins too.
      connection = requireRegisterConnection(await registerConnectionFor(actor, repo.url));
      await rateLimit(`webhook:register:${actor.userId}`, 20);
    }
    const result = await switchOnWebhook(actor, repo.id, connection);
    c.header("cache-control", "no-store");
    return c.json({ url: result.url, secret: result.secret, registering: result.registering }, 201);
  })
  /** Switches it off. A webhook GarnetOps registered in the forge is removed there too (best effort, audited). */
  .delete("/", async (c) => {
    const actor = c.get("actor");
    const { repo, canManage } = await manageable(actor, c.req.param("id") as string);
    if (!canManage) throw forbidden();
    await switchOffWebhook(actor, repo.id);
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
