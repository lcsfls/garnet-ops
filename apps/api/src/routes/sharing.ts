import { schema } from "@garnetops/db";
import { and, asc, eq, isNotNull } from "drizzle-orm";
import { type Context, Hono } from "hono";
import { db } from "../db.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, isAdmin, requireRole } from "../lib/context.ts";
import { notFound, ProblemError } from "../lib/problem.ts";

/**
 * Sharing private repositories with the organisation (ADR 0030). The owner of a private repository shares it, or,
 * as a member, asks owners and admins to; they see only the name and who asks, and approve or decline. An admin can
 * make a shared repository private again for its owner.
 */
const r = schema.repository;

async function setVisibility(id: string, visibility: "organization" | "private") {
  await db.update(r).set({ visibility, shareRequestedAt: null, updatedAt: new Date() }).where(eq(r.id, id));
}

/** Mounted at /repositories/:id: share, ask to share, and make private again. */
export const repositorySharingRoutes = new Hono<AppEnv>()
  .post("/share", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const id = c.req.param("id") as string;
    const [repo] = await db
      .select({ id: r.id, name: r.name, visibility: r.visibility, requested: r.shareRequestedAt })
      .from(r)
      .where(and(eq(r.id, id), eq(r.organizationId, actor.organizationId), eq(r.ownerUserId, actor.userId)))
      .limit(1);
    if (repo?.visibility !== "private") throw notFound("Repository");
    if (isAdmin(actor)) {
      await setVisibility(repo.id, "organization");
      await audit(actor, "repository.shared", { type: "repository", id: repo.id }, { name: repo.name });
      return c.json({ visibility: "organization", shareRequested: false });
    }
    if (!repo.requested) {
      await db
        .update(r)
        .set({ shareRequestedAt: new Date(), updatedAt: new Date() })
        .where(eq(r.id, repo.id));
      await audit(
        actor,
        "repository.share_requested",
        { type: "repository", id: repo.id },
        { name: repo.name },
      );
    }
    return c.json({ visibility: "private", shareRequested: true });
  })
  .post("/unshare", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const id = c.req.param("id") as string;
    const [repo] = await db
      .select({ id: r.id, name: r.name, visibility: r.visibility, owner: r.ownerUserId })
      .from(r)
      .where(and(eq(r.id, id), eq(r.organizationId, actor.organizationId), eq(r.visibility, "organization")))
      .limit(1);
    if (!repo) throw notFound("Repository");
    // Private means private to someone who is still in the organisation.
    const [member] = repo.owner
      ? await db
          .select({ userId: schema.membership.userId })
          .from(schema.membership)
          .where(
            and(
              eq(schema.membership.organizationId, actor.organizationId),
              eq(schema.membership.userId, repo.owner),
            ),
          )
          .limit(1)
      : [];
    if (!member)
      throw new ProblemError(409, "no-owner", "This repository has no owner it could be private to");
    await setVisibility(repo.id, "private");
    await audit(actor, "repository.unshared", { type: "repository", id: repo.id }, { name: repo.name });
    return c.json({ visibility: "private", shareRequested: false });
  });

/** Mounted at /share-requests: what members asked to share, for owners and admins. */
export const shareRequestRoutes = new Hono<AppEnv>()
  .get("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const rows = await db
      .select({ id: r.id, name: r.name, requestedAt: r.shareRequestedAt, requestedBy: schema.user.name })
      .from(r)
      .leftJoin(schema.user, eq(schema.user.id, r.ownerUserId))
      .where(
        and(
          eq(r.organizationId, actor.organizationId),
          eq(r.visibility, "private"),
          isNotNull(r.shareRequestedAt),
        ),
      )
      .orderBy(asc(r.shareRequestedAt));
    return c.json(rows);
  })
  .post("/:id/approve", async (c) => decide(c, "approve"))
  .post("/:id/decline", async (c) => decide(c, "decline"));

async function decide(c: Context<AppEnv>, decision: "approve" | "decline"): Promise<Response> {
  const actor = c.get("actor");
  requireRole(actor, "admin");
  const [repo] = await db
    .select({ id: r.id, name: r.name })
    .from(r)
    .where(
      and(
        eq(r.id, c.req.param("id") as string),
        eq(r.organizationId, actor.organizationId),
        eq(r.visibility, "private"),
        isNotNull(r.shareRequestedAt),
      ),
    )
    .limit(1);
  if (!repo) throw notFound("Share request");
  if (decision === "approve") await setVisibility(repo.id, "organization");
  else await db.update(r).set({ shareRequestedAt: null, updatedAt: new Date() }).where(eq(r.id, repo.id));
  await audit(
    actor,
    decision === "approve" ? "repository.shared" : "repository.share_declined",
    { type: "repository", id: repo.id },
    { name: repo.name },
  );
  return c.body(null, 204);
}
