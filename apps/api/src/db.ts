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
  /** Personal forge connections (ADR 0030): check a token and list what its account can see. */
  forgeConnectionRefresh: "forge-connection.refresh",
  /** Signing in to a forge (ADR 0031): the device flow, or exchanging the code of the authorization code flow. */
  forgeSignIn: "forge-sign-in.run",
  /** Reading the open pull requests again (ADR 0032). */
  pullRequestRefresh: "pull-requests.refresh",
  /**
   * Website monitoring (ADR 0023, a module since ADR 0033): checking the proof of control, and a run of stage 1 (passive) or
   * stage 2 (light active). Not the `exposure.*` names of 0.0.3, which the worker removes on start.
   */
  exposureVerify: "websites.verify",
  exposureRun: "websites.run",
} as const;
