import { createDb } from "@garnetops/db";
import { env } from "./env.ts";

export const { db, pool } = createDb(env.DATABASE_URL, { applicationName: "garnetops-worker" });
