import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { request } from "node:https";
import { newId } from "@garnetops/core";
import {
  isForbiddenAddress,
  type NotifyEvent,
  type NotifyPayload,
  type WebhookFormat,
  webhookBody,
  webhookUrlProblem,
} from "@garnetops/core/notifications";
import { open, type SecretPurpose } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { type Language, resolveLanguage, resources } from "@garnetops/i18n";
import { and, eq, sql } from "drizzle-orm";
import nodemailer from "nodemailer";
import type { PgBoss } from "pg-boss";
import { db } from "./db.ts";
import { env, vaultPrivateKey } from "./env.ts";

export const NOTIFY_QUEUE = "notify.deliver";
const TIMEOUT_MS = 10_000;

type Channel = typeof schema.notificationChannel.$inferSelect;

/** A failure whose message is safe to store and show: never a response body or a secret. */
export class DeliveryError extends Error {}

const fill = (text: string, values: Record<string, string | number>) =>
  text.replace(/\{(\w+)\}/g, (match, key: string) => (key in values ? String(values[key]) : match));

/** Title and body of a notification in the channel's language (ADR 0010: summary and link only). */
export function renderNotification(
  payload: NotifyPayload,
  language: Language,
): { title: string; text: string } {
  const m = resources[language].translation.notify;
  const repository = payload.repository?.name ?? "";
  const [title, body] =
    payload.event === "finding.new_critical"
      ? [
          fill(m.newCriticalTitle, { repository }),
          fill(m.newCriticalText, payload.counts ?? { critical: 0, knownExploited: 0 }),
        ]
      : payload.event === "gate.blocked"
        ? [
            fill(m.gateBlockedTitle, { repository }),
            fill(m.gateBlockedText, { rules: payload.gate?.blockingRules ?? 0 }),
          ]
        : payload.event === "scan.failed"
          ? [fill(m.scanFailedTitle, { repository }), m.scanFailedText]
          : [m.testTitle, m.testText];
  return { title, text: `${body}\n${fill(m.footer, { organization: payload.organization })}` };
}

/**
 * Resolves the webhook's host and refuses loopback, link-local, metadata and similar
 * addresses (ADR 0010). Used as the connection's own lookup, so the address that is
 * checked is the address that is connected to (no DNS rebinding in between).
 */
export function safeLookup(
  hostname: string,
  options: object,
  callback: (error: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void,
): void {
  dnsLookup(hostname, { ...options, all: true }, (error, addresses) => {
    if (error) return callback(error, []);
    const list = addresses as LookupAddress[];
    if (list.length === 0 || list.some((a) => isForbiddenAddress(a.address))) {
      return callback(Object.assign(new Error("refused address"), { code: "EREFUSED_ADDRESS" }), []);
    }
    const wantsAll = (options as { all?: boolean }).all;
    if (wantsAll) return callback(null, list);
    const first = list[0] as LookupAddress;
    callback(null, first.address, first.family);
  });
}

/** POSTs JSON over HTTPS: no redirects, no response body kept, 10 seconds at most. */
export function postJson(
  url: string,
  body: unknown,
  /** Tests only: a lookup and CA for a local HTTPS server. */
  test: { lookup?: typeof safeLookup; ca?: string } = {},
): Promise<void> {
  const lookup = test.lookup ?? safeLookup;
  const problem = webhookUrlProblem(url);
  if (problem) return Promise.reject(new DeliveryError(problem));
  const data = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = request(
      url,
      {
        method: "POST",
        lookup,
        ...(test.ca ? { ca: test.ca } : {}),
        timeout: TIMEOUT_MS,
        headers: {
          "content-type": "application/json",
          "content-length": data.length,
          "user-agent": "GarnetOps",
        },
      },
      (res) => {
        res.resume(); // drain and discard: the answer is never stored or shown
        const status = res.statusCode ?? 0;
        if (status >= 200 && status < 300) resolve();
        else
          reject(
            new DeliveryError(
              status >= 300 && status < 400
                ? `HTTP ${status} (redirects are not followed)`
                : `HTTP ${status}`,
            ),
          );
      },
    );
    req.on("timeout", () => req.destroy(new DeliveryError("timeout")));
    req.on("error", (error: NodeJS.ErrnoException) => {
      if (error instanceof DeliveryError) return reject(error);
      reject(
        new DeliveryError(
          error.code === "EREFUSED_ADDRESS" ? "refused address" : (error.code ?? "connection failed"),
        ),
      );
    });
    req.end(data);
  });
}

async function openSecret(channel: Channel, purpose: SecretPurpose): Promise<string> {
  if (!channel.secretId) throw new DeliveryError("credential missing");
  const [secret] = await db
    .select()
    .from(schema.secret)
    .where(
      and(
        eq(schema.secret.id, channel.secretId),
        eq(schema.secret.organizationId, channel.organizationId),
        eq(schema.secret.purpose, purpose),
      ),
    )
    .limit(1);
  if (!secret) throw new DeliveryError("credential missing");
  const plain = open(
    secret.sealed,
    { organizationId: secret.organizationId, recordId: secret.id, purpose },
    vaultPrivateKey,
  );
  const value = plain.toString("utf8");
  plain.fill(0);
  return value;
}

const recipients = (config: Record<string, unknown>) =>
  (Array.isArray(config.to) ? config.to : []).filter((v): v is string => typeof v === "string");

/** Tests only: a certificate authority for a local SMTP server with a throw-away certificate. */
export interface MailTestOptions {
  ca?: string;
}

async function sendSmtp(
  channel: Channel,
  title: string,
  text: string,
  to: string[],
  test: MailTestOptions = {},
) {
  const c = channel.config;
  const password = c.username ? await openSecret(channel, "smtp-password") : null;
  const transport = nodemailer.createTransport({
    host: String(c.host),
    port: Number(c.port),
    // "tls": TLS from the start (465); "starttls": upgrade required (587); never plain text.
    secure: c.security === "tls",
    requireTLS: c.security !== "tls",
    auth: c.username && password ? { user: String(c.username), pass: password } : undefined,
    connectionTimeout: TIMEOUT_MS,
    greetingTimeout: TIMEOUT_MS,
    socketTimeout: TIMEOUT_MS,
    tls: { minVersion: "TLSv1.2", ...(test.ca ? { ca: test.ca } : {}) },
  });
  try {
    await transport.sendMail({ from: String(c.from), to, subject: title, text });
  } catch (error) {
    const code = (error as { code?: string; responseCode?: number }).code;
    const status = (error as { responseCode?: number }).responseCode;
    throw new DeliveryError(status ? `SMTP ${status}` : (code ?? "SMTP failed"));
  } finally {
    transport.close();
  }
}

async function sendGraph(channel: Channel, title: string, text: string, to: string[]) {
  const c = channel.config;
  const secret = await openSecret(channel, "graph-client-secret");
  const tokenResponse = await fetch(
    `https://login.microsoftonline.com/${encodeURIComponent(String(c.tenantId))}/oauth2/v2.0/token`,
    {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      body: new URLSearchParams({
        client_id: String(c.clientId),
        client_secret: secret,
        scope: "https://graph.microsoft.com/.default",
        grant_type: "client_credentials",
      }),
    },
  ).catch(() => {
    throw new DeliveryError("Microsoft sign-in unreachable");
  });
  if (!tokenResponse.ok) throw new DeliveryError(`Microsoft sign-in HTTP ${tokenResponse.status}`);
  const { access_token: token } = (await tokenResponse.json()) as { access_token?: string };
  if (!token) throw new DeliveryError("Microsoft sign-in returned no token");
  const send = await fetch(
    `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(String(c.from))}/sendMail`,
    {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({
        message: {
          subject: title,
          body: { contentType: "Text", content: text },
          toRecipients: to.map((address) => ({ emailAddress: { address } })),
        },
        saveToSentItems: false,
      }),
    },
  ).catch(() => {
    throw new DeliveryError("Microsoft Graph unreachable");
  });
  await send.body?.cancel();
  if (!send.ok) throw new DeliveryError(`Microsoft Graph HTTP ${send.status}`);
}

/**
 * Sends one message through a mail channel (SMTP or Graph) to the given addresses. Personal
 * notification mail (ADR 0019) uses this with the address of the one person it is for.
 */
export async function sendMailVia(
  channel: Channel,
  title: string,
  text: string,
  to: string[],
  test: MailTestOptions = {},
): Promise<void> {
  if (channel.kind === "smtp") await sendSmtp(channel, title, text, to, test);
  else if (channel.kind === "graph") await sendGraph(channel, title, text, to);
  else throw new DeliveryError("not a mail channel");
}

/** Sends one notification to one channel and records the delivery. Throws so the queue retries. */
export async function deliver(channelId: string, payload: NotifyPayload): Promise<void> {
  const [channel] = await db
    .select()
    .from(schema.notificationChannel)
    .where(eq(schema.notificationChannel.id, channelId))
    .limit(1);
  if (!channel || (!channel.enabled && payload.event !== "test")) return;
  const { title, text } = renderNotification(payload, resolveLanguage(channel.language));
  const record = (status: "sent" | "failed", error: string | null) =>
    db.insert(schema.notificationDelivery).values({
      id: newId("ndl"),
      organizationId: channel.organizationId,
      channelId: channel.id,
      event: payload.event,
      status,
      error,
    });
  try {
    if (channel.kind === "webhook") {
      const url = await openSecret(channel, "webhook-url");
      await postJson(
        url,
        webhookBody((channel.format ?? "generic") as WebhookFormat, payload, title, `${text}`),
      );
    } else if (channel.kind === "smtp") {
      await sendSmtp(channel, title, `${text}\n${payload.link}`, recipients(channel.config));
    } else {
      await sendGraph(channel, title, `${text}\n${payload.link}`, recipients(channel.config));
    }
    await record("sent", null);
  } catch (error) {
    const reason = error instanceof DeliveryError ? error.message : "unexpected error";
    if (!(error instanceof DeliveryError)) console.error(`notify ${channel.id}:`, error);
    await record("failed", reason.slice(0, 200));
    throw error;
  }
}

/**
 * What a finished scan of a repository's own branch is worth telling (ADR 0010). Checks of
 * pull requests are left out: their pipeline already shows the result.
 */
export async function eventsForScan(
  scanId: string,
): Promise<{ organizationId: string; ownerUserId: string | null; payloads: NotifyPayload[] } | null> {
  const [row] = await db
    .select({
      state: schema.scan.state,
      ref: schema.scan.ref,
      organizationId: schema.scan.organizationId,
      organization: schema.organization.name,
      repositoryId: schema.repository.id,
      repositoryName: schema.repository.name,
      ownerUserId: schema.repository.ownerUserId,
      finishedAt: schema.scan.finishedAt,
    })
    .from(schema.scan)
    .innerJoin(schema.repository, eq(schema.repository.id, schema.scan.repositoryId))
    .innerJoin(schema.organization, eq(schema.organization.id, schema.scan.organizationId))
    .where(eq(schema.scan.id, scanId))
    .limit(1);
  if (!row || row.ref) return null;
  const base = {
    organization: row.organization,
    repository: { id: row.repositoryId, name: row.repositoryName },
    link: `${env.PUBLIC_URL ? new URL(env.PUBLIC_URL).origin : ""}/repositories/${row.repositoryId}`,
    at: (row.finishedAt ?? new Date()).toISOString(),
  };
  if (row.state === "failed")
    return {
      organizationId: row.organizationId,
      ownerUserId: row.ownerUserId,
      payloads: [{ ...base, event: "scan.failed" }],
    };
  if (row.state !== "succeeded") return null;

  const payloads: NotifyPayload[] = [];
  const [counts] = await db
    .select({
      critical: sql<number>`count(*) filter (where ${schema.finding.severity} = 'critical')::int`,
      knownExploited: sql<number>`count(*) filter (where ${schema.vulnerability.knownExploited})::int`,
    })
    .from(schema.finding)
    .innerJoin(schema.vulnerability, eq(schema.vulnerability.id, schema.finding.vulnerabilityId))
    .where(and(eq(schema.finding.firstSeenScanId, scanId), eq(schema.finding.state, "open")));
  if (counts && (counts.critical > 0 || counts.knownExploited > 0)) {
    payloads.push({ ...base, event: "finding.new_critical", counts });
  }
  const [gate] = await db
    .select({ result: schema.gateRun.result, matches: schema.gateRun.matches })
    .from(schema.gateRun)
    .where(eq(schema.gateRun.scanId, scanId))
    .limit(1);
  if (gate?.result === "blocked") {
    const blockingRules = Object.values(gate.matches).filter((m) => m.mode === "block").length;
    payloads.push({ ...base, event: "gate.blocked", gate: { blockingRules } });
  }
  return { organizationId: row.organizationId, ownerUserId: row.ownerUserId, payloads };
}

/** Queues one job per subscribed channel and notification. */
export async function queueNotifications(boss: PgBoss, organizationId: string, payloads: NotifyPayload[]) {
  if (payloads.length === 0) return;
  const channels = await db
    .select({ id: schema.notificationChannel.id, events: schema.notificationChannel.events })
    .from(schema.notificationChannel)
    .where(
      and(
        eq(schema.notificationChannel.organizationId, organizationId),
        eq(schema.notificationChannel.enabled, true),
      ),
    );
  for (const payload of payloads) {
    for (const channel of channels.filter((c) =>
      c.events.includes(payload.event as Exclude<NotifyEvent, "test">),
    )) {
      await boss.send(NOTIFY_QUEUE, { channelId: channel.id, payload }, { retryLimit: 2, retryDelay: 60 });
    }
  }
}
