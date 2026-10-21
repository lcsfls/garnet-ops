import { newId } from "@garnetops/core";
import { sql } from "drizzle-orm";
import { db } from "../db.ts";
import { ProblemError } from "./problem.ts";

/**
 * Fixed-window limit kept in the `rate_limit` table (shared with better-auth, under our own
 * key prefixes), so it survives restarts like the sign-in limits (AGENTS.md rule 1).
 * Throws 429 when `key` has had more than `max` requests in the current window.
 */
export async function rateLimit(key: string, max: number, windowMs = 60_000): Promise<void> {
  const now = Date.now();
  const [row] = (
    await db.execute<{ count: number }>(sql`
      insert into rate_limit (id, key, count, last_request)
      values (${newId("rl")}, ${key}, 1, ${now})
      on conflict (key) do update set
        count = case when rate_limit.last_request < ${now - windowMs} then 1 else rate_limit.count + 1 end,
        last_request = case when rate_limit.last_request < ${now - windowMs} then ${now} else rate_limit.last_request end
      returning count`)
  ).rows;
  if ((row?.count ?? 0) > max) {
    throw new ProblemError(429, "rate-limited", "Too many requests, try again in a minute");
  }
}
