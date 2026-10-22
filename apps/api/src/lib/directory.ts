import { newId } from "@garnetops/core";
import { seal } from "@garnetops/core/vault";
import { schema } from "@garnetops/db";
import { asc, eq } from "drizzle-orm";
import { boss, db, QUEUES } from "../db.ts";
import { vaultPublicKey } from "../env.ts";
import { ProblemError } from "./problem.ts";

/**
 * The API's side of the directory sign-in (ADR 0020). The API never talks to the directory and
 * never holds the service account's password in the clear: it queues a request, the worker (the
 * only process that opens the vault) answers it, and the API reads the answer.
 */

export type DirectoryConfigRow = typeof schema.ldapConfig.$inferSelect;

/** How long a person waits for the directory before the API gives up. The worker's own deadline is shorter. */
export const REQUEST_WAIT_MS = 28_000;
const POLL_MS = 80;

/** The organisation whose directory is switched on, or null. GarnetOps has one organisation today. */
export async function activeDirectory(): Promise<DirectoryConfigRow | null> {
  const [row] = await db
    .select({ config: schema.ldapConfig })
    .from(schema.ldapConfig)
    .innerJoin(schema.organization, eq(schema.organization.id, schema.ldapConfig.organizationId))
    .where(eq(schema.ldapConfig.enabled, true))
    .orderBy(asc(schema.organization.createdAt), asc(schema.organization.id))
    .limit(1);
  return row?.config ?? null;
}

export async function directoryOf(organizationId: string): Promise<DirectoryConfigRow | null> {
  const [row] = await db
    .select()
    .from(schema.ldapConfig)
    .where(eq(schema.ldapConfig.organizationId, organizationId))
    .limit(1);
  return row ?? null;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Asks the worker something about the directory and waits for the answer. A password typed at
 * sign-in is sealed for the vault key (only the worker can open it), lives in one row for the
 * length of the request, and is deleted here when the request ends, whatever happens; the worker
 * deletes it as soon as it has taken the request.
 *
 * Throws a 503 problem when the worker does not answer in time.
 */
export async function askDirectory(input: {
  organizationId: string;
  kind: "sign-in" | "test" | "lookup" | "certificate";
  params?: Record<string, string>;
  password?: string;
  requestedBy?: string | null;
  waitMs?: number;
}): Promise<Record<string, unknown>> {
  const id = newId("dir");
  let secretId: string | null = null;
  try {
    if (input.password !== undefined) {
      secretId = newId("sec");
      await db.insert(schema.secret).values({
        id: secretId,
        organizationId: input.organizationId,
        purpose: "ldap-user-password",
        sealed: seal(
          input.password,
          { organizationId: input.organizationId, recordId: secretId, purpose: "ldap-user-password" },
          vaultPublicKey,
        ),
        vaultKeyId: vaultPublicKey.id,
        createdBy: input.requestedBy ?? null,
      });
    }
    await db.insert(schema.directoryRequest).values({
      id,
      organizationId: input.organizationId,
      kind: input.kind,
      params: input.params ?? {},
      passwordSecretId: secretId,
      requestedBy: input.requestedBy ?? null,
    });
    await boss.send(QUEUES.directory, { requestId: id }, { retryLimit: 0, expireInSeconds: 120 });
    const deadline = Date.now() + (input.waitMs ?? REQUEST_WAIT_MS);
    for (;;) {
      const [row] = await db
        .select({ status: schema.directoryRequest.status, result: schema.directoryRequest.result })
        .from(schema.directoryRequest)
        .where(eq(schema.directoryRequest.id, id))
        .limit(1);
      if (row?.status === "done" && row.result) return row.result;
      if (Date.now() > deadline) {
        throw new ProblemError(503, "directory-unavailable", "The directory did not answer in time");
      }
      await sleep(POLL_MS);
    }
  } finally {
    await db
      .delete(schema.directoryRequest)
      .where(eq(schema.directoryRequest.id, id))
      .catch(() => {});
    if (secretId) {
      await db
        .delete(schema.secret)
        .where(eq(schema.secret.id, secretId))
        .catch(() => {});
    }
  }
}
