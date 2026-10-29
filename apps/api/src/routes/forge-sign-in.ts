import { newId } from "@garnetops/core";
import { apiBaseFromWeb, apiBaseProblem, FORGE_KINDS, normalizeForgeWebBase } from "@garnetops/core/fix-prs";
import {
  authorizeUrl,
  CLIENT_ID_PATTERN,
  hashSignInState,
  newSignInSecret,
  pkceChallenge,
  SIGN_IN_TTL_MS,
  signInFlow,
  signInRedirectUri,
} from "@garnetops/core/forge-sign-in";
import { seal } from "@garnetops/core/vault";
import { schema, type Viewer } from "@garnetops/db";
import { and, asc, eq, gt, inArray } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { boss, db, QUEUES } from "../db.ts";
import { env, vaultPublicKey } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { type AppEnv, requireRole } from "../lib/context.ts";
import { notFound, ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

/**
 * Signing in to forges (ADR 0031). Admins register a sign-in application per forge (`/forge-apps`); members sign in with
 * it (`/forge-sign-in`). The API keeps the state of a sign-in and seals what it needs; it never talks to a forge and never
 * sees a token: the worker does both.
 */
const app = schema.forgeApp;
const signIn = schema.forgeSignIn;

const secretField = z
  .string()
  .trim()
  .min(8)
  .max(500)
  .regex(/^[\x21-\x7e]+$/, "Paste the secret as it is");
const createBody = z.object({
  forgeKind: z.enum(FORGE_KINDS),
  webBaseUrl: z.string().trim().max(300),
  apiBaseUrl: z.string().trim().max(300).optional(),
  clientId: z.string().trim().regex(CLIENT_ID_PATTERN, "Paste the client id as the forge shows it"),
  clientSecret: secretField.optional(),
});
const changeBody = z.object({
  clientId: createBody.shape.clientId.optional(),
  /** A new secret, or null to remove it (a public client). */
  clientSecret: secretField.nullable().optional(),
});

function sealAppSecret(organizationId: string, plain: string) {
  const id = newId("sec");
  return {
    id,
    organizationId,
    purpose: "forge-app-secret" as const,
    sealed: seal(plain, { organizationId, recordId: id, purpose: "forge-app-secret" }, vaultPublicKey),
    vaultKeyId: vaultPublicKey.id,
  };
}

const appDto = (row: typeof app.$inferSelect) => ({
  id: row.id,
  forgeKind: row.forgeKind,
  webBaseUrl: row.webBaseUrl,
  apiBaseUrl: row.apiBaseUrl,
  clientId: row.clientId,
  hasSecret: row.secretId !== null,
  flow: signInFlow(row.forgeKind),
  createdAt: row.createdAt,
});

export const forgeAppRoutes = new Hono<AppEnv>()
  /** The sign-in applications (owners and admins), with the redirect address to register at Gitea and Forgejo. */
  .get("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const rows = await db
      .select()
      .from(app)
      .where(eq(app.organizationId, actor.organizationId))
      .orderBy(asc(app.webBaseUrl));
    return c.json({ redirectUri: signInRedirectUri(env.PUBLIC_URL), apps: rows.map(appDto) });
  })
  /** What members can sign in with: forge and address, nothing about the client. */
  .get("/available", async (c) => {
    const actor = c.get("actor");
    const rows = await db
      .select({ id: app.id, forgeKind: app.forgeKind, webBaseUrl: app.webBaseUrl })
      .from(app)
      .where(eq(app.organizationId, actor.organizationId))
      .orderBy(asc(app.webBaseUrl));
    return c.json(rows.map((r) => ({ ...r, flow: signInFlow(r.forgeKind) })));
  })
  .post("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const input = createBody.parse(await c.req.json());
    const webBaseUrl = normalizeForgeWebBase(input.webBaseUrl);
    if (!webBaseUrl) {
      throw new ProblemError(
        422,
        "invalid-web-address",
        "Use the forge's https:// address, without user name or query",
      );
    }
    const apiBaseUrl = (input.apiBaseUrl || apiBaseFromWeb(input.forgeKind, webBaseUrl)).replace(/\/+$/, "");
    const problem = apiBaseProblem(input.forgeKind, apiBaseUrl);
    if (problem) throw new ProblemError(422, "invalid-api-address", problem);
    requireRecentSignIn(actor);
    const [existing] = await db
      .select({ id: app.id })
      .from(app)
      .where(and(eq(app.organizationId, actor.organizationId), eq(app.webBaseUrl, webBaseUrl)))
      .limit(1);
    if (existing) throw new ProblemError(409, "duplicate", "This forge already has a sign-in application");
    const id = newId("fapp");
    const row = await db.transaction(async (tx) => {
      const secret = input.clientSecret ? sealAppSecret(actor.organizationId, input.clientSecret) : null;
      if (secret) await tx.insert(schema.secret).values({ ...secret, createdBy: actor.userId });
      const [created] = await tx
        .insert(app)
        .values({
          id,
          organizationId: actor.organizationId,
          forgeKind: input.forgeKind,
          webBaseUrl,
          apiBaseUrl,
          clientId: input.clientId,
          secretId: secret?.id ?? null,
          createdBy: actor.userId,
        })
        .returning();
      return created as typeof app.$inferSelect;
    });
    await audit(
      actor,
      "forge_app.added",
      { type: "forge_app", id },
      { forge: input.forgeKind, web: webBaseUrl, secret: Boolean(input.clientSecret) },
    );
    return c.json(appDto(row), 201);
  })
  .patch("/:id", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const input = changeBody.parse(await c.req.json());
    requireRecentSignIn(actor);
    const [row] = await db
      .select()
      .from(app)
      .where(and(eq(app.id, c.req.param("id")), eq(app.organizationId, actor.organizationId)))
      .limit(1);
    if (!row) throw notFound("Sign-in application");
    const updated = await db.transaction(async (tx) => {
      let secretId = row.secretId;
      if (input.clientSecret !== undefined) {
        const secret = input.clientSecret ? sealAppSecret(actor.organizationId, input.clientSecret) : null;
        if (secret) await tx.insert(schema.secret).values({ ...secret, createdBy: actor.userId });
        secretId = secret?.id ?? null;
      }
      const [changed] = await tx
        .update(app)
        .set({ clientId: input.clientId ?? row.clientId, secretId, updatedAt: new Date() })
        .where(eq(app.id, row.id))
        .returning();
      if (input.clientSecret !== undefined && row.secretId) {
        await tx.delete(schema.secret).where(eq(schema.secret.id, row.secretId));
      }
      return changed as typeof app.$inferSelect;
    });
    await audit(
      actor,
      "forge_app.changed",
      { type: "forge_app", id: row.id },
      {
        web: row.webBaseUrl,
        clientId: input.clientId !== undefined,
        secret: input.clientSecret !== undefined,
      },
    );
    return c.json(appDto(updated));
  })
  /** Removes the application. Connections made with it keep working until their token has to be renewed. */
  .delete("/:id", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    requireRecentSignIn(actor);
    const [row] = await db
      .delete(app)
      .where(and(eq(app.id, c.req.param("id")), eq(app.organizationId, actor.organizationId)))
      .returning();
    if (!row) throw notFound("Sign-in application");
    if (row.secretId) await db.delete(schema.secret).where(eq(schema.secret.id, row.secretId));
    await audit(actor, "forge_app.removed", { type: "forge_app", id: row.id }, { web: row.webBaseUrl });
    return c.body(null, 204);
  });

/** The caller's own sign-in, else 404. */
async function ownSignIn(viewer: Viewer, id: string) {
  const [row] = await db
    .select()
    .from(signIn)
    .where(
      and(
        eq(signIn.id, id),
        eq(signIn.organizationId, viewer.organizationId),
        eq(signIn.userId, viewer.userId),
      ),
    )
    .limit(1);
  if (!row) throw notFound("Sign-in");
  return row;
}

async function dropSecrets(ids: (string | null)[]) {
  const list = ids.filter((id): id is string => Boolean(id));
  if (list.length) await db.delete(schema.secret).where(inArray(schema.secret.id, list));
}

const startBody = z.object({ appId: z.string().min(1).max(40) });
const callbackBody = z.object({
  state: z.string().min(20).max(200),
  code: z.string().min(1).max(500).optional(),
  /** The forge's `error` parameter when the person declined. */
  error: z.string().max(100).optional(),
});

export const forgeSignInRoutes = new Hono<AppEnv>()
  /**
   * Starts a sign-in. Device flow: the worker asks the forge for a code; the page polls for it. Code flow: the page sends
   * the browser to `authorizeUrl`, and the forge sends it back to the callback page.
   */
  .post("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const input = startBody.parse(await c.req.json());
    await rateLimit(`forge-sign-in:${actor.userId}`, 10);
    const [target] = await db
      .select()
      .from(app)
      .where(and(eq(app.id, input.appId), eq(app.organizationId, actor.organizationId)))
      .limit(1);
    if (!target) throw notFound("Sign-in application");
    const id = newId("fsi");
    const flow = signInFlow(target.forgeKind);
    const expiresAt = new Date(Date.now() + SIGN_IN_TTL_MS);
    if (flow === "device") {
      await db.insert(signIn).values({
        id,
        organizationId: actor.organizationId,
        userId: actor.userId,
        appId: target.id,
        flow,
        expiresAt,
      });
      await boss.send(QUEUES.forgeSignIn, { signInId: id }, { retryLimit: 0, expireInSeconds: 1200 });
      return c.json({ id, flow }, 201);
    }
    const state = newSignInSecret();
    const verifier = newSignInSecret();
    const verifierSecretId = newId("sec");
    await db.transaction(async (tx) => {
      await tx.insert(schema.secret).values({
        id: verifierSecretId,
        organizationId: actor.organizationId,
        purpose: "forge-sign-in",
        sealed: seal(
          verifier,
          { organizationId: actor.organizationId, recordId: verifierSecretId, purpose: "forge-sign-in" },
          vaultPublicKey,
        ),
        vaultKeyId: vaultPublicKey.id,
        createdBy: actor.userId,
      });
      await tx.insert(signIn).values({
        id,
        organizationId: actor.organizationId,
        userId: actor.userId,
        appId: target.id,
        flow,
        state: "waiting",
        stateHash: hashSignInState(state),
        verifierSecretId,
        expiresAt,
      });
    });
    return c.json(
      {
        id,
        flow,
        authorizeUrl: authorizeUrl({
          kind: target.forgeKind,
          webBaseUrl: target.webBaseUrl,
          clientId: target.clientId,
          redirectUri: signInRedirectUri(env.PUBLIC_URL),
          state,
          challenge: pkceChallenge(verifier),
        }),
      },
      201,
    );
  })
  /** Where a sign-in stands; for the device flow, the code to confirm on the forge. */
  .get("/:id", async (c) => {
    const actor = c.get("actor");
    const row = await ownSignIn(actor, c.req.param("id"));
    return c.json({
      id: row.id,
      flow: row.flow,
      state: row.state,
      userCode: row.userCode,
      verificationUri: row.verificationUri,
      expiresAt: row.expiresAt,
      problem: row.problem,
      connectionId: row.connectionId,
    });
  })
  /**
   * The forge sent the browser back (code flow). The state must belong to the caller, be unused and fresh; it can be
   * used once. The code is sealed for the worker, which exchanges it.
   */
  .post("/callback", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "member");
    const input = callbackBody.parse(await c.req.json());
    await rateLimit(`forge-sign-in:${actor.userId}`, 10);
    const [row] = await db
      .update(signIn)
      .set({ stateHash: null, updatedAt: new Date() })
      .where(
        and(
          eq(signIn.stateHash, hashSignInState(input.state)),
          eq(signIn.organizationId, actor.organizationId),
          eq(signIn.userId, actor.userId),
          eq(signIn.flow, "code"),
          eq(signIn.state, "waiting"),
          gt(signIn.expiresAt, new Date()),
        ),
      )
      .returning();
    if (!row)
      throw new ProblemError(
        409,
        "sign-in-unknown",
        "This sign-in is unknown, used or expired. Start again.",
      );
    if (!input.code || input.error) {
      await db
        .update(signIn)
        .set({ state: "failed", problem: "denied", verifierSecretId: null, updatedAt: new Date() })
        .where(eq(signIn.id, row.id));
      await dropSecrets([row.verifierSecretId]);
      return c.json({ id: row.id }, 200);
    }
    const codeSecretId = newId("sec");
    await db.transaction(async (tx) => {
      await tx.insert(schema.secret).values({
        id: codeSecretId,
        organizationId: actor.organizationId,
        purpose: "forge-sign-in",
        sealed: seal(
          input.code as string,
          { organizationId: actor.organizationId, recordId: codeSecretId, purpose: "forge-sign-in" },
          vaultPublicKey,
        ),
        vaultKeyId: vaultPublicKey.id,
        createdBy: actor.userId,
      });
      await tx
        .update(signIn)
        .set({ state: "exchanging", codeSecretId, updatedAt: new Date() })
        .where(eq(signIn.id, row.id));
    });
    await boss.send(QUEUES.forgeSignIn, { signInId: row.id }, { retryLimit: 0, expireInSeconds: 300 });
    return c.json({ id: row.id }, 202);
  })
  /** Cancels a sign-in that has not finished; a waiting device flow stops at its next poll. */
  .delete("/:id", async (c) => {
    const actor = c.get("actor");
    const row = await ownSignIn(actor, c.req.param("id"));
    await db.delete(signIn).where(eq(signIn.id, row.id));
    await dropSecrets([row.verifierSecretId, row.codeSecretId]);
    return c.body(null, 204);
  });
