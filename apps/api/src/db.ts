import { createDb } from "@garnetops/db";
import { PgBoss } from "pg-boss";
import { env } from "./env.ts";

export const { db, pool } = createDb(env.DATABASE_URL, { applicationName: "garnetops-api" });

/** Job queue. The API only sends jobs; the worker consumes them. */
export const boss = new PgBoss({
  connectionString: env.DATABASE_URL,
  application_name: "garnetops-api-queue",
});
boss.on("error", (error) => console.error("queue:", error.message));

export const QUEUES = {
  scanRepository: "scan.repository",
  /** One job per channel and notification, so a retry never repeats a delivery that worked (ADR 0010). */
  notify: "notify.deliver",
  /** Directory sign-in (ADR 0020): a request only the worker can answer, because only it opens the service account's password. */
  directory: "directory.request",
  /** AI triage (ADR 0013): one job per answer, and probes for "load models" and "test connection". */
  aiGenerate: "ai.generate",
  aiProbe: "ai.probe",
  /** Fix pull requests (ADR 0014): one job per request, a check of a write token, and an on-demand status refresh. */
  fixPrCreate: "fix-pr.create",
  fixPrCheck: "fix-pr.check",
  fixPrRefresh: "fix-pr.refresh",
} as const;
