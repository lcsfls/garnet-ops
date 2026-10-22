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
  /** Servers (ADR 0011): the organisation's SSH access key, host key scans and inventories. */
  hostAccessKey: "host.access-key",
  hostKeyscan: "host.keyscan",
  hostInventory: "host.inventory",
  /** Proxmox VE (ADR 0012): reading the certificate a server presents, and the read-only sync. */
  proxmoxCertificate: "proxmox.certificate",
  proxmoxSync: "proxmox.sync",
  /** Wazuh (ADR 0015): reading the certificate of an endpoint, the read-only sync, and the optional AI summary. */
  xdrCertificate: "xdr.certificate",
  xdrSync: "xdr.sync",
  xdrSummary: "xdr.summary",
  /** Attack overview (ADR 0016): the optional AI summary of the aggregates. */
  attackSummary: "attacks.summary",
  /** AI triage (ADR 0013): one job per answer, and probes for "load models" and "test connection". */
  aiGenerate: "ai.generate",
  aiProbe: "ai.probe",
  /** Fix pull requests (ADR 0014): one job per request, a check of a write token, and an on-demand status refresh. */
  fixPrCreate: "fix-pr.create",
  fixPrCheck: "fix-pr.check",
  fixPrRefresh: "fix-pr.refresh",
} as const;
