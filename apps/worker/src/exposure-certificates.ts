/**
 * The certificate expiry warning of website monitoring (ADR 0023, section 8; the amendment of ADR 0033): once per step (30, 14, 7
 * days, expired), again after a renewal, and once per **certificate**: a wildcard certificate served on twelve names is one message
 * for all of them, not twelve. The findings of each asset are not touched here; they stay per asset.
 */

import type { PassiveSnapshot } from "@garnetops/core/exposure";
import { type CertificateNotice, certificateNotice } from "@garnetops/core/exposure-certificates";
import { schema } from "@garnetops/db";
import { and, eq, ne, sql } from "drizzle-orm";
import { db } from "./db.ts";
import { tellUsers } from "./user-notify.ts";

type AssetRow = typeof schema.exposureAsset.$inferSelect;

/**
 * Decides and sends the expiry warning after a stage 1 look and stores the new snapshot with the step, all under a lock per
 * organisation and certificate: two names of one certificate looked at the same time cannot both announce it. Returns the step to
 * store for the asset (the caller writes it again with the rest of the run's results).
 */
export async function announceCertificateExpiry(
  asset: Pick<AssetRow, "id" | "organizationId" | "value" | "certNotifiedLevel">,
  snapshot: PassiveSnapshot,
  now: Date,
): Promise<number | null> {
  const a = schema.exposureAsset;
  const self = {
    id: asset.id,
    value: asset.value,
    notifiedLevel: asset.certNotifiedLevel,
    tls: snapshot.tls,
  };
  // Without a certificate, or without a step due, nothing is compared with the other names.
  const alone = certificateNotice(self, [], now);
  if (!alone.notice) return alone.level;

  const fingerprint = alone.notice.fingerprint;
  const decided = await db.transaction(async (tx) => {
    await tx.execute(
      sql`select pg_advisory_xact_lock(hashtextextended(${`exposure-certificate:${asset.organizationId}:${fingerprint}`}, 0))`,
    );
    const others = await tx
      .select({
        id: a.id,
        value: a.value,
        notifiedLevel: a.certNotifiedLevel,
        tls: sql<unknown>`${a.passive} -> 'tls'`,
      })
      .from(a)
      .where(and(eq(a.organizationId, asset.organizationId), ne(a.id, asset.id)));
    const result = certificateNotice(self, others, now);
    // The snapshot and the step are stored together, so the next name of this certificate sees that it was told.
    await tx.update(a).set({ passive: snapshot, certNotifiedLevel: result.level }).where(eq(a.id, asset.id));
    return result;
  });
  if (decided.notice) await tell(asset, decided.notice);
  return decided.level;
}

/**
 * A certificate on one name is told as before (its name, a link to the website). A certificate on several names is told once,
 * with the first name, how many there are, and a link to the certificates view of that certificate.
 */
async function tell(asset: Pick<AssetRow, "id" | "organizationId" | "value">, notice: CertificateNotice) {
  const expired = notice.level === 0;
  const days = Math.max(notice.days, 0);
  if (notice.names.length <= 1) {
    await tellUsers({
      organizationId: asset.organizationId,
      titleKey: expired ? "exposureCertificateExpired" : "exposureCertificateExpiring",
      params: { asset: asset.value, days },
      link: `/websites/${asset.id}`,
    });
    return;
  }
  await tellUsers({
    organizationId: asset.organizationId,
    titleKey: expired ? "exposureCertificateSharedExpired" : "exposureCertificateSharedExpiring",
    params: { asset: notice.names[0] ?? asset.value, count: notice.names.length, days },
    link: `/websites/certificates?certificate=${encodeURIComponent(notice.fingerprint)}`,
  });
}
