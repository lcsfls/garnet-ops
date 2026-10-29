import { schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { createMiddleware } from "hono/factory";
import { db } from "../db.ts";
import type { AppEnv } from "./context.ts";
import { ProblemError } from "./problem.ts";

/**
 * Modules an organisation switches on (ADR 0033). Website monitoring connects to public hosts an admin names; hosts and
 * containers (ADR 0034) accept reports from agents on the organisation's servers. Both are off until an owner or admin
 * switches them on.
 */
export const MODULES = ["websites", "hosts"] as const;
export type ModuleName = (typeof MODULES)[number];

export async function modulesOf(organizationId: string): Promise<Record<ModuleName, boolean>> {
  const [[websites], [hosts]] = await Promise.all([
    db
      .select({ enabled: schema.exposureSettings.enabled })
      .from(schema.exposureSettings)
      .where(eq(schema.exposureSettings.organizationId, organizationId))
      .limit(1),
    db
      .select({ enabled: schema.hostSettings.enabled })
      .from(schema.hostSettings)
      .where(eq(schema.hostSettings.organizationId, organizationId))
      .limit(1),
  ]);
  return { websites: websites?.enabled === true, hosts: hosts?.enabled === true };
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
