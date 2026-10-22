import { threadChannel } from "@garnetops/core/ai";
import { listenBus } from "./listen-bus.ts";

/** The AI answer streams' view of the shared LISTEN connection (ADR 0013): one channel per thread. */
export const aiBus = {
  /** Starts watching a thread; resolves once PostgreSQL confirmed LISTEN. */
  subscribe(threadId: string, notice: (payload: string) => void, resync: () => void) {
    return listenBus.subscribe(threadChannel(threadId), notice, resync);
  },
  /** Gives the shared connection back (shutdown and tests). */
  close: () => listenBus.close(),
  /** Number of watched channels (tests). */
  get watched() {
    return listenBus.watched;
  },
};
