import { USER_NOTIFICATION_CHANNEL } from "@garnetops/core/user-notifications";
import { listenBus } from "./listen-bus.ts";

interface Subscriber {
  notice: () => void;
  resync: () => void;
}

/**
 * Tells the open notification streams of one person that something new may be waiting (ADR 0019).
 * Every stream of every person shares one subscription to the PostgreSQL channel (and so the
 * shared LISTEN connection); a notice names the person it is for and the streams of others never
 * see it. The notice carries no content: a stream reads the rows from the database itself, with
 * its own person and organisation in the query.
 */
class UserNotificationBus {
  private readonly subscribers = new Map<string, Set<Subscriber>>();
  private subscription: Promise<() => void> | null = null;

  private ensure(): Promise<() => void> {
    this.subscription ??= listenBus
      .subscribe(
        USER_NOTIFICATION_CHANNEL,
        (payload) => {
          let userId: unknown;
          try {
            userId = (JSON.parse(payload) as { u?: unknown }).u;
          } catch {
            return;
          }
          if (typeof userId !== "string") return;
          for (const subscriber of this.subscribers.get(userId) ?? []) subscriber.notice();
        },
        () => {
          for (const set of this.subscribers.values()) for (const subscriber of set) subscriber.resync();
        },
      )
      .catch((error) => {
        this.subscription = null;
        throw error;
      });
    return this.subscription;
  }

  /** Resolves once PostgreSQL confirmed LISTEN, so nothing written after it is missed. */
  async subscribe(userId: string, notice: () => void, resync: () => void): Promise<() => void> {
    const subscriber: Subscriber = { notice, resync };
    let set = this.subscribers.get(userId);
    if (!set) {
      set = new Set();
      this.subscribers.set(userId, set);
    }
    set.add(subscriber);
    try {
      await this.ensure();
    } catch (error) {
      this.remove(userId, subscriber);
      throw error;
    }
    return () => this.remove(userId, subscriber);
  }

  private remove(userId: string, subscriber: Subscriber): void {
    const set = this.subscribers.get(userId);
    set?.delete(subscriber);
    if (set?.size === 0) this.subscribers.delete(userId);
  }

  /** Forgets the subscription (shutdown and tests); the shared connection is closed by `listenBus.close()`. */
  reset(): void {
    this.subscribers.clear();
    this.subscription = null;
  }

  /** Number of people with an open stream (tests). */
  get watching(): number {
    return this.subscribers.size;
  }
}

export const userNotificationBus = new UserNotificationBus();
