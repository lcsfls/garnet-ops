import { Hono } from "hono";
import type { AppEnv } from "../lib/context.ts";
import { APP_VERSION } from "../version.ts";

/** Facts about this installation that every signed-in user may see. */
export const systemRoutes = new Hono<AppEnv>().get("/", (c) => c.json({ version: APP_VERSION }));
