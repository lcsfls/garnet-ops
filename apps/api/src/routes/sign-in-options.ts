import { Hono } from "hono";
import { activeDirectory } from "../lib/directory.ts";
import { clientIp } from "../lib/ip.ts";
import { rateLimit } from "../lib/rate-limit.ts";

/**
 * What the sign-in page may offer before anyone is signed in (ADR 0020): whether signing in with
 * the directory is switched on. Nothing else about the configuration is public.
 */
export const signInOptionsRoutes = new Hono().get("/", async (c) => {
  await rateLimit(`sign-in-options:${clientIp(c.req.raw.headers) ?? "unknown"}`, 60);
  c.header("cache-control", "no-store");
  return c.json({ directory: Boolean(await activeDirectory()) });
});
