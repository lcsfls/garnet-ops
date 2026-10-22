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

/**
 * Failure counters for the directory sign-in (ADR 0020), kept in the same table and with the
 * same fixed windows. Unlike {@link rateLimit} they only count what went wrong, so a person who
 * signs in correctly again and again is never throttled, and what is counted can stay far below
 * the account lock-out threshold of a typical directory.
 */
export async function failureCount(key: string, windowMs: number): Promise<number> {
  const [row] = (
    await db.execute<{ count: number }>(sql`
      select count from rate_limit where key = ${key} and last_request >= ${Date.now() - windowMs}`)
  ).rows;
  return row?.count ?? 0;
}

/** Counts one failure for `key`; the window starts with the first failure. */
export async function recordFailure(key: string, windowMs: number): Promise<void> {
  const now = Date.now();
  await db.execute(sql`
    insert into rate_limit (id, key, count, last_request)
    values (${newId("rl")}, ${key}, 1, ${now})
    on conflict (key) do update set
      count = case when rate_limit.last_request < ${now - windowMs} then 1 else rate_limit.count + 1 end,
      last_request = case when rate_limit.last_request < ${now - windowMs} then ${now} else rate_limit.last_request end`);
}

/** Forgets the failures of `key` (after a success). */
export async function clearFailures(key: string): Promise<void> {
  await db.execute(sql`delete from rate_limit where key = ${key}`);
}
