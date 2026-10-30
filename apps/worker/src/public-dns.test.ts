import { describe, expect, it, vi } from "vitest";

vi.mock("./db.ts", () => ({ db: null }));

const { firstAnswer, lookupFor, racingResolver } = await import("./public-dns.ts");
const { PUBLIC_DNS_PROVIDERS } = await import("@garnetops/core/public-dns");
type DnsLike = import("./exposure-net.ts").DnsLike;

const fail = (code: string) => Object.assign(new Error(code), { code });
const later = (ms: number, value: unknown) =>
  new Promise<unknown>((resolve, reject) =>
    setTimeout(() => (value instanceof Error ? reject(value) : resolve(value)), ms),
  );

describe("public DNS next to the local resolver", () => {
  it("offers exactly Cloudflare, Google and Quad9 with their well-known addresses", () => {
    expect(Object.keys(PUBLIC_DNS_PROVIDERS)).toEqual(["cloudflare", "google", "quad9"]);
    expect(PUBLIC_DNS_PROVIDERS.cloudflare.servers[0]).toBe("1.1.1.1");
    expect(PUBLIC_DNS_PROVIDERS.google.servers[0]).toBe("8.8.8.8");
    expect(PUBLIC_DNS_PROVIDERS.quad9.servers[0]).toBe("9.9.9.9");
  });

  it("takes the first clear answer, so a slow local resolver no longer holds a check up", async () => {
    const started = Date.now();
    await expect(firstAnswer(later(2000, ["192.0.2.1"]), later(10, ["192.0.2.1"]))).resolves.toEqual([
      "192.0.2.1",
    ]);
    expect(Date.now() - started).toBeLessThan(1000);
    // "No such record" is an answer as well.
    await expect(firstAnswer(later(2000, ["x"]), later(10, fail("ENODATA")))).rejects.toMatchObject({
      code: "ENODATA",
    });
  });

  it("waits for the other resolver when one fails, and reports the local error when both do", async () => {
    await expect(firstAnswer(later(10, fail("ETIMEOUT")), later(30, ["192.0.2.2"]))).resolves.toEqual([
      "192.0.2.2",
    ]);
    await expect(firstAnswer(later(30, ["192.0.2.3"]), later(10, fail("ESERVFAIL")))).resolves.toEqual([
      "192.0.2.3",
    ]);
    await expect(
      firstAnswer(later(10, fail("ETIMEOUT")), later(20, fail("ESERVFAIL"))),
    ).rejects.toMatchObject({
      code: "ETIMEOUT",
    });
  });

  it("asks both resolvers for every kind of record", async () => {
    const asked: string[] = [];
    const fake = (who: string, ms: number): DnsLike =>
      new Proxy({} as DnsLike, {
        get: (_, method: string) => (name: string) => {
          asked.push(`${who}:${method}:${name}`);
          return later(ms, [[`${who}-answer`]]);
        },
      });
    const dns = racingResolver(fake("local", 500), fake("public", 5));
    expect(await dns.resolveTxt("_garnetops-challenge.example.com")).toEqual([["public-answer"]]);
    expect(asked).toEqual([
      "local:resolveTxt:_garnetops-challenge.example.com",
      "public:resolveTxt:_garnetops-challenge.example.com",
    ]);
  });

  it("keeps the address policy for outgoing HTTPS: a private answer is refused, whoever gives it", async () => {
    expect(lookupFor(null)).toBeUndefined();
    const extra = { resolve4: async () => ["10.0.0.5"], resolve6: async () => [] } as unknown as DnsLike;
    const lookup = lookupFor("quad9", extra);
    const result = await new Promise<{ error: NodeJS.ErrnoException | null }>((resolve) =>
      lookup?.("internal.invalid", {}, (error) => resolve({ error })),
    );
    expect(result.error?.code).toBe("EREFUSED_ADDRESS");
  });
});
