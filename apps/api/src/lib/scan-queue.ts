/** Queues one scan (ADR 0005, 0008, 0045); shared by the routes that start scans, so none of them imports another. */
import { newId } from "@garnetops/core";
import { schema } from "@garnetops/db";
import { boss, db, QUEUES } from "../db.ts";

export async function queueScan(
  organizationId: string,
  repositoryId: string,
  requestedBy: string | null,
  trigger: "manual" | "schedule" | "webhook" | "ci",
  /** Gate checks of another ref (ADR 0008): scanned on their own, never changing the repository's findings. */
  check: { ref: string | null; expectedSha: string | null } = { ref: null, expectedSha: null },
): Promise<string> {
  const scanId = newId("scan");
  await db.insert(schema.scan).values({
    id: scanId,
    organizationId,
    repositoryId,
    state: "queued",
    trigger,
    requestedBy,
    ref: check.ref,
    expectedSha: check.expectedSha,
    // Millisecond precision on purpose: this column is a pagination key (see lib/paginate.ts).
    createdAt: new Date(),
  });
  await boss.send(
    QUEUES.scanRepository,
    { scanId },
    // One job per repository and ref at a time; a check of a pull request does not wait for the nightly scan.
    {
      singletonKey: check.ref ? `${repositoryId}@${check.ref}@${check.expectedSha ?? ""}` : repositoryId,
      retryLimit: 1,
      expireInSeconds: 1800,
    },
  );
  return scanId;
}
