import { type Database, schema } from "@garnetops/db";
import { type JournalEvent, syncJournal, type UpdaterClient } from "@restow-backup/cicd-updater";
import { eq, sql } from "drizzle-orm";

/**
 * Copies the update sidecar's journal into the audit log, exactly once (ADR 0007).
 *
 * The sidecar journals every update action with who asked for it (scheduled, cancelled,
 * started, succeeded, failed, acknowledged, ...). Each event is written together with
 * the cursor in one transaction, and the unique index on (source, event_id) drops a
 * repeat, so restarts and several API processes never duplicate or lose an entry.
 * Events recorded while GarnetOps was down for the update arrive when it is back.
 */

const SOURCE = "updater";
const CURSOR_ID = 1;
/** Event details are the sidecar's own (codes, versions); capped so one event cannot bloat the log. */
const MAX_DETAILS_BYTES = 8_192;

export interface JournalStore {
  loadCursor(): Promise<string | null>;
  ingest(event: JournalEvent): Promise<void>;
  recordGap(after: string | null): Promise<void>;
}

function details(event: JournalEvent): Record<string, unknown> {
  const text = JSON.stringify(event.details ?? {});
  return text.length <= MAX_DETAILS_BYTES ? event.details : { truncated: true };
}

export function journalStore(db: Database): JournalStore {
  /** The requester's organisation, so organisation admins see the entry; null for the system. */
  async function actorOf(userId: string | null) {
    if (!userId) return { userId: null, organizationId: null };
    const [row] = await db
      .select({ userId: schema.user.id, organizationId: schema.membership.organizationId })
      .from(schema.user)
      .leftJoin(schema.membership, eq(schema.membership.userId, schema.user.id))
      .where(eq(schema.user.id, userId))
      .limit(1);
    return { userId: row?.userId ?? null, organizationId: row?.organizationId ?? null };
  }

  return {
    async loadCursor() {
      const [row] = await db
        .select({ last: schema.updaterJournalCursor.lastEventId })
        .from(schema.updaterJournalCursor)
        .where(eq(schema.updaterJournalCursor.id, CURSOR_ID));
      return row?.last ?? null;
    },

    async ingest(event) {
      const who = await actorOf(event.actor.via === "api" ? event.actor.id : null);
      await db.transaction(async (tx) => {
        await tx
          .insert(schema.auditLog)
          .values({
            organizationId: who.organizationId,
            actorUserId: who.userId,
            action: event.action,
            targetType: "update",
            targetId: event.runId,
            data: {
              ...details(event),
              version: event.target,
              by: event.actor.label,
              via: event.actor.via,
            },
            source: SOURCE,
            eventId: event.id,
            createdAt: new Date(event.at),
          })
          .onConflictDoNothing({ target: [schema.auditLog.source, schema.auditLog.eventId] });
        await tx
          .insert(schema.updaterJournalCursor)
          .values({ id: CURSOR_ID, lastEventId: event.id })
          .onConflictDoUpdate({
            target: schema.updaterJournalCursor.id,
            set: { lastEventId: event.id, updatedAt: sql`now()` },
          });
      });
    },

    async recordGap(after) {
      // Visible to every organisation's admins: entries of the update log may be missing.
      await db
        .insert(schema.auditLog)
        .values({
          action: "update.journal_gap",
          data: { after },
          source: SOURCE,
          eventId: `gap-${after ?? "start"}-${Date.now()}`,
        })
        .onConflictDoNothing({ target: [schema.auditLog.source, schema.auditLog.eventId] });
    },
  };
}

/**
 * Polls every 30 seconds while idle and every 3 seconds while an update is scheduled or
 * running. Returns a function that stops it.
 */
export function startJournalSync(
  client: UpdaterClient,
  store: JournalStore,
  log: (message: string) => void = (m) => console.error(m),
): () => void {
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const round = async (): Promise<number> => {
    const state = await client.state();
    if (!state) return 30_000; // no sidecar on this installation
    await syncJournal({
      client,
      loadCursor: () => store.loadCursor(),
      ingest: (event) => store.ingest(event),
      onGap: ({ after }) => store.recordGap(after),
    });
    return state.phase === "scheduled" || state.phase === "running" ? 3_000 : 30_000;
  };

  const loop = (): void => {
    round()
      .catch((error: unknown) => {
        log(`updater: journal sync failed: ${(error as Error).message}`);
        return 30_000;
      })
      .then((delay) => {
        if (stopped) return;
        timer = setTimeout(loop, delay);
        timer.unref?.();
      });
  };
  loop();

  return () => {
    stopped = true;
    clearTimeout(timer);
  };
}
