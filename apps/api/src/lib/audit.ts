import { schema } from "@garnetops/db";
import { db } from "../db.ts";

/**
 * Appends to the audit log. Never pass secrets, tokens or code in `data`.
 * Failures to write the audit log fail the request: an action that cannot be
 * audited does not happen.
 */
export async function audit(
  /** Who acted; user and organisation are null for e.g. a failed sign-in to an unknown account. */
  actor: { organizationId: string | null; userId: string | null; ip: string | null } | null,
  action: string,
  target?: { type: string; id: string },
  data?: Record<string, unknown>,
): Promise<void> {
  await db.insert(schema.auditLog).values({
    organizationId: actor?.organizationId ?? null,
    actorUserId: actor?.userId ?? null,
    action,
    targetType: target?.type ?? null,
    targetId: target?.id ?? null,
    ip: actor?.ip ?? null,
    data: data ?? null,
  });
}
