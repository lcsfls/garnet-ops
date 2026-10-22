import { pool } from "../db.ts";

/** The part of a pg client this module uses (the API does not depend on the pg types directly). */
interface PoolClient {
  query(sql: string): Promise<unknown>;
  on(event: "notification", handler: (message: { channel: string; payload?: string }) => void): unknown;
  on(event: "error" | "end", handler: () => void): unknown;
  release(destroy?: boolean): void;
}

/** Channel names are ours; this keeps them plain identifiers (they are quoted into LISTEN). */
const CHANNEL = /^[a-z][a-z0-9_]{0,62}$/;

/**
 * One PostgreSQL connection that LISTENs for the channels somebody is watching, shared by every
 * event stream of this process (ADR 0013, ADR 0019): the AI answer streams and the notification
 * streams. The worker (or a route) announces what it wrote with NOTIFY; this relays those
 * notices to the handlers of the streams.
 *
 * A connection can break. Then it is replaced, every channel is listened to again, and each
 * subscriber is told to start over from the stored state (`onResync`): notices sent while the
 * connection was down are not lost to the user, because the database holds the text.
 */
class ListenBus {
  private client: PoolClient | null = null;
  private connecting: Promise<PoolClient> | null = null;
  private readonly channels = new Map<
    string,
    Set<{ notice: (payload: string) => void; resync: () => void }>
  >();
  /** LISTEN per channel, so every subscriber waits for the same confirmation, not only the first. */
  private readonly listening = new Map<string, Promise<void>>();
  private retry: NodeJS.Timeout | null = null;

  /** Starts watching a channel. Resolves once PostgreSQL confirmed LISTEN, so nothing after it is missed. */
  async subscribe(
    channel: string,
    notice: (payload: string) => void,
    resync: () => void,
  ): Promise<() => void> {
    if (!CHANNEL.test(channel)) throw new Error("Invalid channel name");
    const subscriber = { notice, resync };
    let set = this.channels.get(channel);
    if (!set) {
      set = new Set();
      this.channels.set(channel, set);
    }
    set.add(subscriber);
    try {
      let ready = this.listening.get(channel);
      if (!ready) {
        const started = this.connect().then(async (client) => {
          await client.query(`LISTEN "${channel}"`);
        });
        ready = started;
        this.listening.set(channel, started);
        started.catch(() => {
          if (this.listening.get(channel) === started) this.listening.delete(channel);
        });
      }
      await ready;
    } catch (error) {
      this.remove(channel, subscriber);
      throw error;
    }
    return () => this.remove(channel, subscriber);
  }

  private remove(channel: string, subscriber: object): void {
    const set = this.channels.get(channel);
    if (!set) return;
    set.delete(subscriber as never);
    if (set.size === 0) {
      this.channels.delete(channel);
      this.listening.delete(channel);
      this.client?.query(`UNLISTEN "${channel}"`).catch(() => {});
    }
  }

  private connect(): Promise<PoolClient> {
    if (this.client) return Promise.resolve(this.client);
    this.connecting ??= (pool.connect() as unknown as Promise<PoolClient>)
      .then((client) => {
        client.on("notification", (message) => {
          if (!message.payload) return;
          for (const subscriber of this.channels.get(message.channel) ?? [])
            subscriber.notice(message.payload);
        });
        const lost = () => this.lost(client);
        client.on("error", lost);
        client.on("end", lost);
        this.client = client;
        return client;
      })
      .finally(() => {
        this.connecting = null;
      });
    return this.connecting;
  }

  private lost(client: PoolClient): void {
    if (this.client !== client) return;
    this.client = null;
    try {
      client.release(true); // destroys the broken connection instead of returning it to the pool
    } catch {
      // already released
    }
    this.scheduleRetry();
  }

  private scheduleRetry(): void {
    if (this.retry || this.channels.size === 0) return;
    this.retry = setTimeout(async () => {
      this.retry = null;
      try {
        const fresh = await this.connect();
        for (const channel of this.channels.keys()) await fresh.query(`LISTEN "${channel}"`);
        for (const set of this.channels.values()) for (const subscriber of set) subscriber.resync();
      } catch {
        // Replace whatever connection we got and try again; the streams keep their stored state meanwhile.
        if (this.client) this.lost(this.client);
        else this.scheduleRetry();
      }
    }, 1_000);
    this.retry.unref();
  }

  /** Gives the connection back (shutdown and tests). */
  async close(): Promise<void> {
    if (this.retry) clearTimeout(this.retry);
    this.retry = null;
    this.channels.clear();
    this.listening.clear();
    const client = this.client;
    this.client = null;
    if (client) {
      await client.query("UNLISTEN *").catch(() => {});
      client.release();
    }
  }

  /** Number of watched channels (tests). */
  get watched(): number {
    return this.channels.size;
  }
}

export const listenBus = new ListenBus();
