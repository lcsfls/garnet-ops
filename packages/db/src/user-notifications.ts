import {
  type EventContext,
  isTitleKey,
  type NotificationParams,
  type Preference,
  RETENTION,
  safeAppLink,
  sanitizeParams,
  selectRecipients,
  TITLE_EVENTS,
  type TitleKey,
  USER_NOTIFICATION_CHANNEL,
  type UserNotificationNotice,
} from "@garnetops/core/user-notifications";
import { and, eq, inArray, sql } from "drizzle-orm";
import type { Database } from "./index.ts";
import { membership, notificationChannel, notificationPreference, userNotification } from "./schema.ts";

export interface NotifyUsersInput {
  organizationId: string;
  titleKey: TitleKey;
  params?: Record<string, unknown>;
  /** A path inside the app (`/repositories/repo_1`); anything else is refused. */
  link: string;
  context?: EventContext;
}

export interface NotifyUsersResult {
  /** People who got a notification in the app. */
  inApp: number;
  /** People with a personal mail waiting for the worker. */
  mail: number;
}

/** Whether the organisation has a mail channel (SMTP or Graph) that personal mail can use. */
export async function mailChannelAvailable(db: Database, organizationId: string): Promise<boolean> {
  const [row] = await db
    .select({ id: notificationChannel.id })
    .from(notificationChannel)
    .where(
      and(
        eq(notificationChannel.organizationId, organizationId),
        eq(notificationChannel.enabled, true),
        inArray(notificationChannel.kind, ["smtp", "graph"]),
      ),
    )
    .limit(1);
  return Boolean(row);
}

/**
 * Creates the notifications of one event for the people who are to be told (ADR 0019): the role
 * decides first, then each person's own choices and scope. Rows and the PostgreSQL NOTIFY for the
 * live streams are written in one transaction, so a stream never hears of a row that is not there
 * yet. Each person keeps their newest 500 notifications.
 *
 * Throws only for a programming error (an unknown title key, a link that is not an app path);
 * callers log it and carry on, because a notification must never fail the work it reports.
 */
export async function notifyUsers(db: Database, input: NotifyUsersInput): Promise<NotifyUsersResult> {
  if (!isTitleKey(input.titleKey)) throw new RangeError(`Unknown notification title: ${input.titleKey}`);
  const link = safeAppLink(input.link);
  if (!link) throw new RangeError("A notification link must be a path inside the app");
  const event = TITLE_EVENTS[input.titleKey];
  const params: NotificationParams = sanitizeParams(input.params);

  const members = await db
    .select({ userId: membership.userId, role: membership.role })
    .from(membership)
    .where(eq(membership.organizationId, input.organizationId));
  if (members.length === 0) return { inApp: 0, mail: 0 };
  const stored = await db
    .select()
    .from(notificationPreference)
    .where(
      and(
        eq(notificationPreference.organizationId, input.organizationId),
        eq(notificationPreference.event, event),
        inArray(
          notificationPreference.userId,
          members.map((m) => m.userId),
        ),
      ),
    );
  const preferences = new Map<string, Partial<Preference>>(
    stored.map((p) => [p.userId, { inApp: p.inApp, email: p.email, scope: p.scope }]),
  );
  const recipients = selectRecipients({
    event,
    members,
    preferences,
    ...(input.context ? { context: input.context } : {}),
    mailAvailable: await mailChannelAvailable(db, input.organizationId),
  });
  if (recipients.length === 0) return { inApp: 0, mail: 0 };

  await db.transaction(async (tx) => {
    const rows = await tx
      .insert(userNotification)
      .values(
        recipients.map((r) => ({
          userId: r.userId,
          organizationId: input.organizationId,
          event,
          titleKey: input.titleKey,
          params,
          link,
          inApp: r.inApp,
          // A copy that is not shown in the app counts as read, so it never adds to a badge.
          readAt: r.inApp ? null : sql`now()`,
          mailState: r.email ? ("pending" as const) : ("none" as const),
        })),
      )
      .returning({ id: userNotification.id, userId: userNotification.userId, inApp: userNotification.inApp });
    for (const row of rows) {
      if (!row.inApp) continue;
      const notice: UserNotificationNotice = { u: row.userId, id: row.id };
      await tx.execute(sql`select pg_notify(${USER_NOTIFICATION_CHANNEL}, ${JSON.stringify(notice)})`);
    }
    for (const userId of new Set(rows.map((r) => r.userId))) {
      await tx.execute(sql`
        delete from user_notification
        where user_id = ${userId}
          and id not in (
            select id from user_notification where user_id = ${userId} order by id desc limit ${RETENTION.maxPerUser}
          )`);
    }
  });
  return {
    inApp: recipients.filter((r) => r.inApp).length,
    mail: recipients.filter((r) => r.email).length,
  };
}

/** Deletes notifications older than the retention period. Returns how many went. */
export async function pruneUserNotifications(db: Database): Promise<number> {
  const result = await db.execute(
    sql`delete from user_notification where created_at < now() - make_interval(days => ${RETENTION.days})`,
  );
  return result.rowCount ?? 0;
}
