import { type NotifyUsersInput, notifyUsers as write } from "@garnetops/db";
import { db } from "../db.ts";

/**
 * Creates personal notifications for an event the API just handled (ADR 0019). A notification
 * never fails the action it reports: problems are logged by name only, never with their text.
 */
export async function notifyUsers(input: NotifyUsersInput): Promise<void> {
  try {
    await write(db, input);
  } catch (error) {
    console.error("notification:", (error as Error)?.name ?? "error");
  }
}
