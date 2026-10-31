/**
 * The two optional keys of the installation's own vulnerability database build: a GitHub token for the GitHub Advisory Database
 * (sent only to api.github.com) and an NVD API key (sent only to services.nvd.nist.gov). Installation-wide, one row in
 * `vulndb_build_settings`; owners and admins read and change them. A key is sealed at once with the vault and never read back:
 * the API only seals, the worker opens it and hands it to the builder for one build. Setting a key sends it to an outside host
 * whenever a build runs, so it needs a recent sign-in (step-up) and an explicit acknowledgement; every change is audited.
 */

import { newId } from "@garnetops/core";
import { type SecretPurpose, seal } from "@garnetops/core/vault";
import {
  VULNDB_BUILD_HOSTS,
  VULNDB_BUILD_KEYS,
  VULNDB_BUILD_SETTINGS_ID,
} from "@garnetops/core/vulndb-build";
import { schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { z } from "zod";
import { db } from "../db.ts";
import { vaultPublicKey } from "../env.ts";
import { audit } from "../lib/audit.ts";
import { type Actor, type AppEnv, requireRole } from "../lib/context.ts";
import { ProblemError } from "../lib/problem.ts";
import { requireRecentSignIn } from "../lib/step-up.ts";

const s = schema.vulnDbBuildSettings;
type Row = typeof s.$inferSelect;

const iso = (d: Date | null | undefined) => (d ? d.toISOString() : null);

function invalid(field: string, code: string): ProblemError {
  return new ProblemError(422, "validation", "The request is not valid", undefined, {
    errors: [{ path: field, message: code }],
  });
}

const githubBody = z.object({
  token: z.string().trim().regex(VULNDB_BUILD_KEYS.githubToken),
  /** Acknowledges that the token is sent to api.github.com whenever the database is built. */
  acknowledged: z.boolean().optional(),
});
const nvdBody = z.object({
  key: z.string().trim().regex(VULNDB_BUILD_KEYS.nvdApiKey),
  /** Acknowledges that the key is sent to services.nvd.nist.gov whenever the database is built. */
  acknowledged: z.boolean().optional(),
});

/** The columns and vault purpose of each key, and the names of its audit actions. */
const KEYS = {
  github: {
    purpose: "vulndb-github-token",
    host: VULNDB_BUILD_HOSTS.githubToken,
    secretId: "githubSecretId",
    organizationId: "githubOrganizationId",
    setBy: "githubSetBy",
    setAt: "githubSetAt",
    audit: {
      set: "vulndb.github_token_set",
      replaced: "vulndb.github_token_replaced",
      removed: "vulndb.github_token_removed",
    },
  },
  nvd: {
    purpose: "vulndb-nvd-api-key",
    host: VULNDB_BUILD_HOSTS.nvdApiKey,
    secretId: "nvdSecretId",
    organizationId: "nvdOrganizationId",
    setBy: "nvdSetBy",
    setAt: "nvdSetAt",
    audit: {
      set: "vulndb.nvd_key_set",
      replaced: "vulndb.nvd_key_replaced",
      removed: "vulndb.nvd_key_removed",
    },
  },
} as const satisfies Record<
  string,
  {
    purpose: SecretPurpose;
    host: string;
    secretId: keyof Row;
    organizationId: keyof Row;
    setBy: keyof Row;
    setAt: keyof Row;
    audit: { set: string; replaced: string; removed: string };
  }
>;
type KeyName = keyof typeof KEYS;

const TARGET = { type: "vulndb_build", id: VULNDB_BUILD_SETTINGS_ID };

/**
 * A key counts as set while its secret row and the organisation it belongs to exist. Deleting that organisation deletes the
 * secret (cascade) and clears `*_organization_id`; the key is then gone and has to be set again.
 */
const configured = (row: Row | undefined, name: KeyName) =>
  Boolean(row?.[KEYS[name].secretId] && row?.[KEYS[name].organizationId]);

/** Seals the value for the vault, stores it as this key and deletes the previous secret, in one transaction. */
async function setKey(actor: Actor, name: KeyName, value: string): Promise<void> {
  const k = KEYS[name];
  const now = new Date();
  const id = newId("sec");
  // The row exists before it is locked, so two changes at once cannot both keep their secret.
  await db.insert(s).values({ id: VULNDB_BUILD_SETTINGS_ID }).onConflictDoNothing({ target: s.id });
  const replaced = await db.transaction(async (tx) => {
    const [row] = await tx.select().from(s).where(eq(s.id, VULNDB_BUILD_SETTINGS_ID)).for("update");
    await tx.insert(schema.secret).values({
      id,
      organizationId: actor.organizationId,
      purpose: k.purpose,
      sealed: seal(
        value,
        { organizationId: actor.organizationId, recordId: id, purpose: k.purpose },
        vaultPublicKey,
      ),
      vaultKeyId: vaultPublicKey.id,
      createdBy: actor.userId,
    });
    await tx
      .update(s)
      .set({
        [k.secretId]: id,
        [k.organizationId]: actor.organizationId,
        [k.setBy]: actor.userId,
        [k.setAt]: now,
        updatedAt: now,
      })
      .where(eq(s.id, VULNDB_BUILD_SETTINGS_ID));
    const previous = row?.[k.secretId] as string | null | undefined;
    if (previous) await tx.delete(schema.secret).where(eq(schema.secret.id, previous));
    return configured(row, name);
  });
  await audit(actor, replaced ? k.audit.replaced : k.audit.set, TARGET, { host: k.host });
}

/** Deletes the key's secret and clears its columns. Nothing to do when none is set. */
async function removeKey(actor: Actor, name: KeyName): Promise<void> {
  const k = KEYS[name];
  const removed = await db.transaction(async (tx) => {
    const [row] = await tx.select().from(s).where(eq(s.id, VULNDB_BUILD_SETTINGS_ID)).for("update");
    const previous = row?.[k.secretId] as string | null | undefined;
    if (!previous) return false;
    await tx
      .update(s)
      .set({
        [k.secretId]: null,
        [k.organizationId]: null,
        [k.setBy]: null,
        [k.setAt]: null,
        updatedAt: new Date(),
      })
      .where(eq(s.id, VULNDB_BUILD_SETTINGS_ID));
    await tx.delete(schema.secret).where(eq(schema.secret.id, previous));
    return true;
  });
  if (removed) await audit(actor, k.audit.removed, TARGET, { host: k.host });
}

export const vulnDbBuildRoutes = new Hono<AppEnv>()
  /** Whether each key is set, when and by whom. Never a key. */
  .get("/", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const [row] = await db.select().from(s).where(eq(s.id, VULNDB_BUILD_SETTINGS_ID)).limit(1);
    const view = async (name: KeyName) => {
      const k = KEYS[name];
      const on = configured(row, name);
      const setBy = on ? (row?.[k.setBy] as string | null) : null;
      // The name of the person is shown only within their own organisation; other organisations see when, not who.
      const sameOrganization = row?.[k.organizationId] === actor.organizationId;
      let setByName: string | null = null;
      if (setBy && sameOrganization) {
        const [u] = await db
          .select({ name: schema.user.name })
          .from(schema.user)
          .where(eq(schema.user.id, setBy))
          .limit(1);
        setByName = u?.name ?? null;
      }
      return { configured: on, setAt: on ? iso(row?.[k.setAt] as Date | null) : null, setBy: setByName };
    };
    return c.json({ github: await view("github"), nvd: await view("nvd") }, 200, {
      "cache-control": "no-store",
    });
  })
  .put("/github-token", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const body = githubBody.parse(await c.req.json());
    if (body.acknowledged !== true) throw invalid("acknowledged", "acknowledgement_required");
    requireRecentSignIn(actor);
    await setKey(actor, "github", body.token);
    return c.json({ ok: true });
  })
  .delete("/github-token", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    await removeKey(actor, "github");
    return c.body(null, 204);
  })
  .put("/nvd-api-key", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    const body = nvdBody.parse(await c.req.json());
    if (body.acknowledged !== true) throw invalid("acknowledged", "acknowledgement_required");
    requireRecentSignIn(actor);
    await setKey(actor, "nvd", body.key);
    return c.json({ ok: true });
  })
  .delete("/nvd-api-key", async (c) => {
    const actor = c.get("actor");
    requireRole(actor, "admin");
    await removeKey(actor, "nvd");
    return c.body(null, 204);
  });
