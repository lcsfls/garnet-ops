/**
 * Public download of the host setup script (ADR 0011). A server that is being set up has no
 * session, so the link carries its own authority: a random token that works once, for
 * SETUP_LINK_MINUTES minutes, and only for the script it was made for. The token is stored
 * hashed. The script holds no secret (the access key's public half and the allowed source
 * addresses), and the one-line installer checks its SHA-256 before it runs anything.
 *
 * Registered before the session middleware, so no cookies are involved. Every unknown, used,
 * expired or malformed token gets the same plain 404.
 */
import { renderSetupScript } from "@garnetops/core/host-setup";
import { schema } from "@garnetops/db";
import { and, eq, gt, isNull } from "drizzle-orm";
import { Hono } from "hono";
import { db } from "../db.ts";
import { clientIp } from "../lib/ip.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { hashToken } from "./hosts.ts";

const l = schema.hostSetupLink;
const NOT_FOUND = { type: "about:blank", title: "Not found", status: 404 };

export const hostSetupPublicRoutes = new Hono().get("/:token", async (c) => {
  const ip = clientIp(c.req.raw.headers);
  // Per address, in the shared rate limit table, so guessing is slow and survives restarts.
  await rateLimit(`host-setup-download:${ip ?? "unknown"}`, 30, 60_000);
  const token = c.req.param("token");
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return c.json(NOT_FOUND, 404);

  const tokenHash = hashToken(token);
  const [link] = await db
    .select()
    .from(l)
    .where(and(eq(l.tokenHash, tokenHash), isNull(l.usedAt), gt(l.expiresAt, new Date())))
    .limit(1);
  if (!link) return c.json(NOT_FOUND, 404);
  const [key] = await db
    .select()
    .from(schema.hostAccessKey)
    .where(eq(schema.hostAccessKey.id, link.accessKeyId))
    .limit(1);
  if (!key) return c.json(NOT_FOUND, 404);

  // The link promises one exact script (its SHA-256 is in the command the admin copied); if the
  // template or the key changed since, serving something else would make the checksum fail anyway.
  const rendered = renderSetupScript({ publicKey: key.publicKey, allowedSource: link.allowedSource });
  if (rendered.sha256 !== link.scriptSha256)
    return c.json({ type: "about:blank", title: "Link outdated", status: 410 }, 410);

  // Claim it atomically: of two simultaneous downloads only one wins.
  const claimed = await db
    .update(l)
    .set({ usedAt: new Date(), usedIp: ip })
    .where(and(eq(l.id, link.id), isNull(l.usedAt)))
    .returning({ id: l.id });
  if (claimed.length === 0) return c.json(NOT_FOUND, 404);
  await db.insert(schema.auditLog).values({
    organizationId: link.organizationId,
    actorUserId: null,
    action: "host.setup_script_downloaded",
    targetType: "host_setup_link",
    targetId: link.id,
    ip,
    data: { sha256: link.scriptSha256, allowedSource: link.allowedSource },
  });
  return c.body(rendered.script, 200, {
    "content-type": "text/x-shellscript; charset=utf-8",
    "content-disposition": `attachment; filename="${rendered.filename}"`,
    "cache-control": "no-store",
  });
});
