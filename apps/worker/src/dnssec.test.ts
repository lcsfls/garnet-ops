import { readFileSync } from "node:fs";
import { evaluatePassive } from "@garnetops/core/exposure";
import dnsPacket from "dns-packet";
import { describe, expect, it } from "vitest";
import {
  type DnskeyData,
  type DsData,
  dsMatches,
  evaluateDnssec,
  keyTag,
  type RrsigData,
  readDnssec,
  type SoaData,
  signatureValid,
  type WireQuery,
} from "./dnssec.ts";
import type { DnsLike } from "./exposure-net.ts";

/** Signed zones made by dnspython, an independent implementation, for RSA/SHA-256, ECDSA P-256 and P-384, and Ed25519. */
const vectors = JSON.parse(readFileSync(new URL("../test/dnssec-vectors.json", import.meta.url), "utf8")) as {
  zone: string;
  inception: number;
  expiration: number;
  cases: {
    algorithm: number;
    ksk: { rdata: string; keyTag: number };
    zsk: { rdata: string; keyTag: number };
    soa: string;
    rrsigKsk: string;
    rrsigSoa: string;
    ds: string[];
  }[];
};

type Codec = { decode(buf: Buffer): unknown };
const codec = dnsPacket as unknown as Record<"dnskey" | "rrsig" | "ds" | "soa", Codec>;
/** dns-packet's record decoders read the two-byte length first. */
const decode = <T>(type: "dnskey" | "rrsig" | "ds" | "soa", hex: string): T => {
  const rdata = Buffer.from(hex, "hex");
  const prefix = Buffer.alloc(2);
  prefix.writeUInt16BE(rdata.length);
  return codec[type].decode(Buffer.concat([prefix, rdata])) as T;
};

const inside = new Date((vectors.inception + 86_400) * 1000);
function zoneOf(c: (typeof vectors.cases)[number]) {
  const ksk = decode<DnskeyData>("dnskey", c.ksk.rdata);
  const zsk = decode<DnskeyData>("dnskey", c.zsk.rdata);
  return {
    ksk,
    zsk,
    ds: c.ds.map((hex) => decode<DsData>("ds", hex)),
    keySig: decode<RrsigData>("rrsig", c.rrsigKsk),
    soaSig: decode<RrsigData>("rrsig", c.rrsigSoa),
    soa: decode<SoaData>("soa", c.soa),
  };
}

describe("DNSSEC checks against signatures made by another implementation", () => {
  for (const c of vectors.cases) {
    it(`algorithm ${c.algorithm}: key tags, DS digests and both signatures check out`, () => {
      const z = zoneOf(c);
      expect(keyTag(z.ksk)).toBe(c.ksk.keyTag);
      expect(keyTag(z.zsk)).toBe(c.zsk.keyTag);
      for (const ds of z.ds) expect(dsMatches(ds, "Example.COM", z.ksk)).toBe(true);
      expect(dsMatches(z.ds[0] as DsData, vectors.zone, z.zsk)).toBe(false);
      const keyRdatas = [z.ksk, z.zsk].map((k) => Buffer.from(c[k === z.ksk ? "ksk" : "zsk"].rdata, "hex"));
      expect(signatureValid(z.keySig, vectors.zone, "DNSKEY", keyRdatas, z.ksk)).toBe(true);
      // The SOA in the vector has upper-case names: the canonical form lowercases them before checking.
      const soaRdata = Buffer.from(c.soa, "hex");
      expect(soaRdata.toString("latin1")).toContain("Example");
      const snapshot = evaluateDnssec({
        zone: vectors.zone,
        ds: z.ds,
        keys: [z.ksk, z.zsk],
        keySigs: [z.keySig],
        soa: z.soa,
        soaSigs: [z.soaSig],
        now: inside,
      });
      expect(snapshot).toMatchObject({ state: "secure", problem: null });
      expect(snapshot.signatures.every((s) => s.valid === true)).toBe(true);
      expect(snapshot.expiresAt).toBe(new Date(vectors.expiration * 1000).toISOString());
    });
  }

  const base = zoneOf(vectors.cases[1] as (typeof vectors.cases)[number]);
  const input = {
    zone: vectors.zone,
    ds: base.ds,
    keys: [base.ksk, base.zsk],
    keySigs: [base.keySig],
    soa: base.soa,
    soaSigs: [base.soaSig],
    now: inside,
  };

  it("finds a tampered signature, a changed record and a DS that names no key", () => {
    const flipped = Buffer.from(base.soaSig.signature);
    flipped[5] = (flipped[5] as number) ^ 0xff;
    expect(evaluateDnssec({ ...input, soaSigs: [{ ...base.soaSig, signature: flipped }] })).toMatchObject({
      state: "broken",
      problem: "soaSignatureInvalid",
    });
    expect(evaluateDnssec({ ...input, soa: { ...base.soa, serial: base.soa.serial + 1 } }).problem).toBe(
      "soaSignatureInvalid",
    );
    const otherDs = { ...(base.ds[0] as DsData), digest: Buffer.alloc(32, 7) };
    expect(evaluateDnssec({ ...input, ds: [otherDs] })).toMatchObject({
      state: "broken",
      problem: "dsNoMatch",
    });
    expect(evaluateDnssec({ ...input, keySigs: [] }).problem).toBe("dnskeyNotSigned");
  });

  it("calls expired signatures expired, and tells unsigned from signed-but-not-delegated", () => {
    const after = new Date((vectors.expiration + 60) * 1000);
    expect(evaluateDnssec({ ...input, now: after })).toMatchObject({
      state: "broken",
      problem: "signatureExpired",
    });
    expect(evaluateDnssec({ ...input, ds: [], keys: [], keySigs: [], soaSigs: [] }).state).toBe("unsigned");
    expect(evaluateDnssec({ ...input, ds: [] }).state).toBe("insecure");
    expect(evaluateDnssec({ ...input, keys: [], keySigs: [] }).problem).toBe("noDnskey");
  });

  it("turns the state into findings: broken is high, a day before expiry is medium, SHA-1-only DS is low", () => {
    const findings = (dnssec: ReturnType<typeof evaluateDnssec>, now = inside) =>
      evaluatePassive(
        {
          version: 1,
          takenAt: now.toISOString(),
          kind: "domain",
          name: "www.example.com",
          addresses: [],
          nonPublic: [],
          dns: {
            failed: [],
            a: [],
            aaaa: [],
            cname: [],
            mx: [],
            ns: [],
            caa: [],
            caaFound: true,
            spf: { records: 1, policy: "fail", record: "v=spf1 -all" },
            dmarc: { found: true, policy: "reject", record: "v=DMARC1; p=reject" },
            dnssec,
          },
          ptr: [],
          tls: [],
          http: null,
          plain: null,
          resolves: false,
          httpsOpen: false,
        },
        now,
      )
        .filter((f) => f.rule.startsWith("dnssec"))
        .map((f) => `${f.rule}:${f.severity}`);
    expect(findings(evaluateDnssec(input))).toEqual([]);
    expect(findings(evaluateDnssec({ ...input, keySigs: [] }))).toEqual(["dnssecBroken:high"]);
    expect(findings(evaluateDnssec({ ...input, ds: [], keys: [], keySigs: [], soaSigs: [] }))).toEqual([
      "dnssecMissing:low",
    ]);
    expect(findings(evaluateDnssec({ ...input, ds: [] }))).toEqual(["dnssecNotDelegated:medium"]);
    const late = new Date((vectors.expiration - 3600) * 1000);
    expect(findings(evaluateDnssec({ ...input, now: late }), late)).toEqual(["dnssecExpiring:medium"]);
    expect(findings(evaluateDnssec({ ...input, ds: [base.ds[1] as DsData] }))).toEqual([
      "dnssecSha1Digest:low",
    ]);
  });
});

describe("asking the name servers", () => {
  const noData = () => Object.assign(new Error("no data"), { code: "ENODATA" });
  const dns = {
    resolveNs: async (name: string) => {
      if (name === "example.com") return ["ns1.example.com"];
      if (name === "com") return ["a.gtld.example.net"];
      throw noData();
    },
    resolve4: async (name: string) => {
      if (name === "ns1.example.com") return ["192.0.2.53"];
      if (name === "a.gtld.example.net") return ["198.51.100.53"];
      throw noData();
    },
    resolve6: async () => {
      throw noData();
    },
  } as unknown as DnsLike;
  const z = zoneOf(vectors.cases[2] as (typeof vectors.cases)[number]);

  it("asks the parent for DS and the zone for DNSKEY and SOA, at public addresses only", async () => {
    const asked: string[] = [];
    const dnsWire: WireQuery = async (server, name, type) => {
      asked.push(`${server} ${name} ${type}`);
      if (type === "DS") return { records: z.ds, rrsigs: [] };
      if (type === "DNSKEY") return { records: [z.ksk, z.zsk], rrsigs: [z.keySig] };
      return { records: [z.soa], rrsigs: [z.soaSig] };
    };
    const result = await readDnssec({ dns, allowTestRanges: true, dnsWire }, "www.example.com", inside);
    expect(result).toMatchObject({ zone: "example.com", state: "secure" });
    expect(asked.sort()).toEqual([
      "192.0.2.53 example.com DNSKEY",
      "192.0.2.53 example.com SOA",
      "198.51.100.53 example.com DS",
    ]);
  });

  it("says unknown when the name servers do not answer, so findings are left as they are", async () => {
    const dnsWire: WireQuery = async () => undefined;
    expect(await readDnssec({ dns, allowTestRanges: true, dnsWire }, "example.com", inside)).toBe("unknown");
    // Name servers at non-public addresses are never asked.
    expect(
      await readDnssec({ dns, dnsWire: async () => ({ records: [], rrsigs: [] }) }, "example.com", inside),
    ).toBe("unknown");
  });
});
