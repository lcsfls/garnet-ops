import { schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { createMiddleware } from "hono/factory";
import { db } from "../db.ts";
import type { AppEnv } from "./context.ts";
import { ProblemError } from "./problem.ts";

/**
 * Modules an organisation switches on (ADR 0033). Website monitoring is the first: it connects to public hosts an admin
 * names, so it is off until an owner or admin switches it on.
 */
export const MODULES = ["websites"] as const;
export type ModuleName = (typeof MODULES)[number];

export async function modulesOf(organizationId: string): Promise<Record<ModuleName, boolean>> {
  const [row] = await db
    .select({ enabled: schema.exposureSettings.enabled })
    .from(schema.exposureSettings)
    .where(eq(schema.exposureSettings.organizationId, organizationId))
    .limit(1);
  return { websites: row?.enabled === true };
}

/** Answers 409 `module-off` for every route of a module that is switched off. */
export const requireModule = (name: ModuleName) =>
  createMiddleware<AppEnv>(async (c, next) => {
    const modules = await modulesOf(c.get("actor").organizationId);
    if (!modules[name]) {
      throw new ProblemError(409, "module-off", "This module is switched off", undefined, { module: name });
    }
    await next();
  });
