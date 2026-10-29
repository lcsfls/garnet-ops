import { newId } from "@garnetops/core";
import {
  type ChannelFilters,
  channelFiltersSchema,
  NOTIFY_EVENTS,
  type NotifyPayload,
  WEBHOOK_FORMATS,
  webhookUrlProblem,
} from "@garnetops/core/notifications";
import { type SecretPurpose, seal } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { LANGUAGES } from "@garnetops/i18n";
import { and, desc, eq, inArray } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { boss, db, QUEUES } from "../db.ts";
import { env, vaultPublicKey } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

const ch = schema.notificationChannel;
const events = z.array(z.enum(NOTIFY_EVENTS)).min(1).max(NOTIFY_EVENTS.length);
const recipients = z.array(z.string().trim().toLowerCase().email().max(254)).min(1).max(20);
const common = {
  name: z.string().trim().min(1).max(80),
  events,
  language: z.enum(LANGUAGES).default("en"),
  filters: channelFiltersSchema.default({}),
};
const host = z
  .string()
  .trim()
  .min(1)
  .max(253)
  .regex(/^[A-Za-z0-9.-]+$/, "Use a host name or address");

const createBody = z.discriminatedUnion("kind", [
  z.object({
    ...common,
    kind: z.literal("webhook"),
    format: z.enum(WEBHOOK_FORMATS),
    url: z
      .string()
      .trim()
      .max(2000)
      .refine((url) => webhookUrlProblem(url) === null, {
        message: "Use an https:// address that is not loopback, link-local or a metadata address",
      }),
  }),
  z.object({
    ...common,
    kind: z.literal("smtp"),
    host,
    port: z.number().int().min(1).max(65535),
    security: z.enum(["tls", "starttls"]),
    username: z.string().trim().max(254).optional(),
    password: z.string().max(500).optional(),
    from: z.string().trim().toLowerCase().email().max(254),
    to: recipients,
  }),
  z.object({
    ...common,
    kind: z.literal("graph"),
    tenantId: z
      .string()
      .trim()
      .regex(/^[A-Za-z0-9.-]{1,100}$/, "Use the directory (tenant) id"),
    clientId: z
      .string()
      .trim()
      .regex(/^[0-9a-fA-F-]{36}$/, "Use the application (client) id"),
    clientSecret: z.string().min(1).max(500),
    from: z.string().trim().toLowerCase().email().max(254),
    to: recipients,
  }),
]);

const patchBody = z.object({
  name: common.name.optional(),
  events: events.optional(),
  language: z.enum(LANGUAGES).optional(),
  enabled: z.boolean().optional(),
  filters: channelFiltersSchema.optional(),
});

/**
 * Keeps only what a filter means: shared repositories of this organisation (each once, an unknown or private id is
 * refused)
 * and a minimum severity. No repositories means every repository.
 */
async function checkedFilters(organizationId: string, filters: ChannelFilters): Promise<ChannelFilters> {
  const ids = [...new Set(filters.repositoryIds ?? [])];
  if (ids.length > 0) {
    const known = await db
      .select({ id: schema.repository.id })
      .from(schema.repository)
      .where(
        and(
          eq(schema.repository.organizationId, organizationId),
          // A channel reaches the whole organisation: private repositories (ADR 0030) are never chosen for one.
          eq(schema.repository.visibility, "organization"),
          inArray(schema.repository.id, ids),
        ),
      );
    if (known.length !== ids.length) {
      throw new ProblemError(
        422,
        "validation",
        "Choose repositories shared with this organisation",
        undefined,
        {
          errors: [
            { path: "filters.repositoryIds", message: "Choose repositories shared with this organisation" },
          ],
        },
      );
    }
  }
  return {
    ...(filters.minSeverity ? { minSeverity: filters.minSeverity } : {}),
    ...(ids.length > 0 ? { repositoryIds: ids } : {}),
  };
}

async function storeSecret(organizationId: string, userId: string, purpose: SecretPurpose, plain: string) {
  const id = newId("sec");
  await db.insert(schema.secret).values({
    id,
    organizationId,
    purpose,
    sealed: seal(plain, { organizationId, recordId: id, purpose }, vaultPublicKey),
    vaultKeyId: vaultPublicKey.id,
    createdBy: userId,
  });
  return id;
}

async function ownChannel(organizationId: string, id: string) {
  const [row] = await db
    .select()
    .from(ch)
    .where(and(eq(ch.id, id), eq(ch.organizationId, organizationId)))
    .limit(1);
  if (!row) throw notFound("Channel");
  return row;
}

/** Notification channels for owners and admins (ADR 0010). Secrets are sealed and never returned. */
export const notificationRoutes = new Hono<AppEnv>()
  .use("*", async (c, next) => {
    requireRole(c.get("actor"), "admin");
    await next();
  })
  .get("/channels", async (c) => {
    const actor = c.get("actor");
    const channels = await db
      .select()
      .from(ch)
      .where(eq(ch.organizationId, actor.organizationId))
      .orderBy(ch.createdAt);
    const ids = channels.map((x) => x.id);
    const deliveries = ids.length
      ? await db
          .selectDistinctOn([schema.notificationDelivery.channelId], {
            channelId: schema.notificationDelivery.channelId,
            status: schema.notificationDelivery.status,
            error: schema.notificationDelivery.error,
            event: schema.notificationDelivery.event,
            createdAt: schema.notificationDelivery.createdAt,
          })
          .from(schema.notificationDelivery)
          .where(inArray(schema.notificationDelivery.channelId, ids))
          .orderBy(schema.notificationDelivery.channelId, desc(schema.notificationDelivery.createdAt))
      : [];
    const last = new Map(deliveries.map(({ channelId, ...d }) => [channelId, d]));
    return c.json(
      channels.map((x) => ({
        id: x.id,
        name: x.name,
        kind: x.kind,
        format: x.format,
        language: x.language,
        events: x.events,
        filters: x.filters,
        enabled: x.enabled,
        // Only what is not secret: the webhook's host, the mail server and addresses.
        config: x.config,
        lastDelivery: last.get(x.id) ?? null,
      })),
    );
  })
  .post("/channels", async (c) => {
    const actor = c.get("actor");
    const input = createBody.parse(await c.req.json());
    requireRecentSignIn(actor);
    const filters = await checkedFilters(actor.organizationId, input.filters);
    const id = newId("nch");
    let secretId: string | null = null;
    let config: Record<string, unknown>;
    if (input.kind === "webhook") {
      secretId = await storeSecret(actor.organizationId, actor.userId, "webhook-url", input.url);
      config = { host: new URL(input.url).host };
    } else if (input.kind === "smtp") {
      if (input.username && !input.password) {
        throw new ProblemError(422, "validation", "Enter the password for this user", undefined, {
          errors: [{ path: "password", message: "Enter the password for this user" }],
        });
      }
      secretId = input.password
        ? await storeSecret(actor.organizationId, actor.userId, "smtp-password", input.password)
        : null;
      config = {
        host: input.host,
        port: input.port,
        security: input.security,
        username: input.username || null,
        from: input.from,
        to: input.to,
      };
    } else {
      secretId = await storeSecret(
        actor.organizationId,
        actor.userId,
        "graph-client-secret",
        input.clientSecret,
      );
      config = { tenantId: input.tenantId, clientId: input.clientId, from: input.from, to: input.to };
    }
    await db.insert(ch).values({
      id,
      organizationId: actor.organizationId,
      name: input.name,
      kind: input.kind,
      format: input.kind === "webhook" ? input.format : null,
      language: input.language,
      events: input.events,
      filters,
      config,
      secretId,
      createdBy: actor.userId,
    });
    await audit(
      actor,
      "notification.channel_created",
      { type: "notification_channel", id },
      {
        name: input.name,
        kind: input.kind,
        events: input.events,
        filters,
        target:
          input.kind === "webhook"
            ? config.host
            : input.kind === "smtp"
              ? `${input.host}:${input.port}`
              : "graph.microsoft.com",
      },
    );
    return c.json({ id }, 201);
  })
  .patch("/channels/:id", async (c) => {
    const actor = c.get("actor");
    const { filters: requested, ...input } = patchBody.parse(await c.req.json());
    const before = await ownChannel(actor.organizationId, c.req.param("id"));
    const filters = requested ? await checkedFilters(actor.organizationId, requested) : undefined;
    await db
      .update(ch)
      .set({ ...input, ...(filters ? { filters } : {}), updatedAt: new Date() })
      .where(eq(ch.id, before.id));
    await audit(
      actor,
      "notification.channel_changed",
      { type: "notification_channel", id: before.id },
      {
        name: before.name,
        ...input,
        ...(filters ? { filters } : {}),
      },
    );
    return c.body(null, 204);
  })
  .delete("/channels/:id", async (c) => {
    const actor = c.get("actor");
    const row = await ownChannel(actor.organizationId, c.req.param("id"));
    await db.transaction(async (tx) => {
      await tx.delete(ch).where(eq(ch.id, row.id));
      if (row.secretId) await tx.delete(schema.secret).where(eq(schema.secret.id, row.secretId));
    });
    await audit(
      actor,
      "notification.channel_deleted",
      { type: "notification_channel", id: row.id },
      { name: row.name },
    );
    return c.body(null, 204);
  })
  /** Queues a test message; the worker sends it and records the delivery. */
  .post("/channels/:id/test", async (c) => {
    const actor = c.get("actor");
    const row = await ownChannel(actor.organizationId, c.req.param("id"));
    const [org] = await db
      .select({ name: schema.organization.name })
      .from(schema.organization)
      .where(eq(schema.organization.id, actor.organizationId));
    const payload: NotifyPayload = {
      event: "test",
      organization: org?.name ?? "",
      repository: null,
      link: new URL(env.PUBLIC_URL).origin,
      at: new Date().toISOString(),
    };
    await boss.send(QUEUES.notify, { channelId: row.id, payload }, { retryLimit: 0 });
    await audit(
      actor,
      "notification.test_sent",
      { type: "notification_channel", id: row.id },
      { name: row.name },
    );
    return c.json({ queued: true }, 202);
  })
  .get("/channels/:id/deliveries", async (c) => {
    const actor = c.get("actor");
    const row = await ownChannel(actor.organizationId, c.req.param("id"));
    const rows = await db
      .select({
        id: schema.notificationDelivery.id,
        event: schema.notificationDelivery.event,
        status: schema.notificationDelivery.status,
        error: schema.notificationDelivery.error,
        createdAt: schema.notificationDelivery.createdAt,
      })
      .from(schema.notificationDelivery)
      .where(eq(schema.notificationDelivery.channelId, row.id))
      .orderBy(desc(schema.notificationDelivery.createdAt))
      .limit(10);
    return c.json(rows);
  });
