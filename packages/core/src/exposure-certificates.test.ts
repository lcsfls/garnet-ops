import { describe, expect, it } from "vitest";
import type { TlsSnapshot } from "./exposure.ts";
import {
  type CertificateSource,
  certificateNotice,
  groupCertificates,
  isWildcardName,
  type NoticeAsset,
  nameCovers,
  sanDnsName,
  servedCertificates,
  sharedCertificates,
  soonestCertificate,
  wildcardMiss,
} from "./exposure-certificates.ts";

const NOW = new Date("2026-11-05T12:00:00Z");
const DAY = 86_400_000;
const inDays = (days: number) => new Date(NOW.getTime() + days * DAY + 3_600_000).toISOString();

/** A handshake on port 443 that presented a certificate; the fingerprint names the certificate. */
function handshake(
  fingerprint: string,
  over: { address?: string; days?: number; sans?: string[]; nameMatches?: boolean | null } = {},
): TlsSnapshot {
  return {
    address: over.address ?? "93.184.216.34",
    port: 443,
    ok: true,
    error: null,
    protocol: "TLSv1.3",
    cipher: "TLS_AES_256_GCM_SHA384",
    trusted: over.nameMatches !== false,
    trustError: over.nameMatches === false ? "ERR_TLS_CERT_ALTNAME_INVALID" : null,
    nameMatches: over.nameMatches === undefined ? true : over.nameMatches,
    cert: {
      subject: "*.example.com",
      issuer: "Example CA",
      sans: over.sans ?? ["DNS:*.example.com"],
      validFrom: "2026-08-01T00:00:00.000Z",
      validTo: inDays(over.days ?? 60),
      fingerprint,
      keyType: "ec",
      keyBits: 256,
      selfSigned: false,
    },
    chainLength: 2,
    legacy: null,
  };
}

describe("names and wildcards", () => {
  it("reads DNS names from alternative names with and without the DNS: prefix, never addresses", () => {
    expect(sanDnsName("DNS:*.Example.com")).toBe("*.example.com");
    expect(sanDnsName("www.example.com")).toBe("www.example.com");
    expect(sanDnsName("IP:192.0.2.1")).toBeNull();
    expect(sanDnsName("IP Address:192.0.2.1")).toBeNull();
    expect(isWildcardName("*.example.com")).toBe(true);
    expect(isWildcardName("www.example.com")).toBe(false);
  });

  it("covers exactly one label with a wildcard, like browsers do", () => {
    expect(nameCovers("*.example.com", "www.example.com")).toBe(true);
    expect(nameCovers("*.example.com", "example.com")).toBe(false);
    expect(nameCovers("*.example.com", "a.b.example.com")).toBe(false);
    expect(nameCovers("*.example.com", "wwwexample.com")).toBe(false);
    expect(nameCovers("example.com", "EXAMPLE.com.")).toBe(true);
  });

  it("says why a wildcard does not cover the domain itself or a deeper name", () => {
    const sans = ["DNS:*.example.com"];
    expect(wildcardMiss("example.com", sans)).toEqual({ wildcard: "*.example.com", reason: "apex" });
    expect(wildcardMiss("a.b.example.com", sans)).toEqual({ wildcard: "*.example.com", reason: "deeper" });
    expect(wildcardMiss("www.example.com", sans)).toBeNull();
    // Another name of the certificate covers it: no miss to explain.
    expect(wildcardMiss("example.com", [...sans, "DNS:example.com"])).toBeNull();
    // No wildcard near the name: nothing to explain either.
    expect(wildcardMiss("www.example.org", sans)).toBeNull();
  });
});

describe("reading snapshots", () => {
  it("skips handshakes without a certificate and entries from older or broken snapshots", () => {
    const failed: TlsSnapshot = { ...handshake("AA"), ok: false, error: "refused", cert: null };
    expect(servedCertificates([failed, { cert: { validTo: "2027-01-01T00:00:00Z" } }, "x", null])).toEqual(
      [],
    );
    expect(servedCertificates(null)).toEqual([]);
    expect(servedCertificates([handshake("AA")])).toHaveLength(1);
  });

  it("finds the certificate that expires first", () => {
    const tls = [
      handshake("LATER", { days: 50 }),
      handshake("SOONER", { address: "93.184.216.35", days: 9 }),
    ];
    expect(soonestCertificate(tls, NOW)).toMatchObject({ fingerprint: "SOONER", days: 9 });
    expect(soonestCertificate([], NOW)).toBeNull();
  });
});

describe("groupCertificates", () => {
  const sources: CertificateSource[] = [
    // One wildcard certificate on three names, one of them on two addresses.
    { id: "exa_1", value: "www.example.com", tls: [handshake("WILD", { days: 20 })] },
    {
      id: "exa_2",
      value: "api.example.com",
      tls: [handshake("WILD", { days: 20 }), handshake("WILD", { address: "93.184.216.35", days: 20 })],
    },
    // The apex is not covered by the wildcard: the name check failed.
    { id: "exa_3", value: "example.com", tls: [handshake("WILD", { days: 20, nameMatches: false })] },
    // Its own certificate, expiring sooner.
    {
      id: "exa_4",
      value: "shop.example.org",
      tls: [handshake("SHOP", { days: 5, sans: ["DNS:shop.example.org"] })],
    },
    // Nothing seen yet.
    { id: "exa_5", value: "new.example.com", tls: null },
  ];

  it("makes one entry per certificate with every name that served it, the soonest expiry first", () => {
    const groups = groupCertificates(sources, NOW);
    expect(groups.map((g) => g.fingerprint)).toEqual(["SHOP", "WILD"]);
    const wild = groups[1];
    expect(wild?.assets.map((x) => x.value)).toEqual(["api.example.com", "example.com", "www.example.com"]);
    expect(wild).toMatchObject({ wildcards: ["*.example.com"], days: 20, level: 30, issuer: "Example CA" });
    expect(groups[0]).toMatchObject({ wildcards: [], days: 5, level: 7 });
  });

  it("lists an asset once with all its addresses, and explains a wildcard that does not cover it", () => {
    const wild = groupCertificates(sources, NOW).find((g) => g.fingerprint === "WILD");
    expect(wild?.assets.find((x) => x.id === "exa_2")?.addresses).toEqual(["93.184.216.34", "93.184.216.35"]);
    expect(wild?.assets.find((x) => x.id === "exa_3")).toMatchObject({
      nameMatches: false,
      wildcardMiss: { wildcard: "*.example.com", reason: "apex" },
    });
    expect(wild?.assets.find((x) => x.id === "exa_1")?.wildcardMiss).toBeNull();
  });

  it("tells each asset which other names serve its certificate", () => {
    expect(sharedCertificates("exa_1", sources, NOW)).toEqual([
      {
        fingerprint: "WILD",
        others: [
          { id: "exa_2", value: "api.example.com" },
          { id: "exa_3", value: "example.com" },
        ],
      },
    ]);
    expect(sharedCertificates("exa_4", sources, NOW)).toEqual([{ fingerprint: "SHOP", others: [] }]);
    expect(sharedCertificates("exa_5", sources, NOW)).toEqual([]);
  });
});

describe("certificateNotice: once per certificate and step", () => {
  const asset = (
    id: string,
    value: string,
    tls: unknown,
    notifiedLevel: number | null = null,
  ): NoticeAsset => ({
    id,
    value,
    tls,
    notifiedLevel,
  });

  it("tells about a certificate on one name exactly as before: once per step, again after a renewal", () => {
    const first = certificateNotice(asset("a", "www.example.com", [handshake("C1", { days: 10 })]), [], NOW);
    expect(first).toEqual({
      level: 14,
      notice: { fingerprint: "C1", level: 14, days: 10, names: ["www.example.com"] },
    });
    // Same step again: nothing.
    expect(
      certificateNotice(asset("a", "www.example.com", [handshake("C1", { days: 9 })], 14), [], NOW),
    ).toEqual({
      level: 14,
      notice: null,
    });
    // A more urgent step: told again.
    expect(
      certificateNotice(asset("a", "www.example.com", [handshake("C1", { days: 6 })], 14), [], NOW).notice,
    ).toMatchObject({ level: 7 });
    // Renewed: the step is forgotten.
    expect(
      certificateNotice(asset("a", "www.example.com", [handshake("C2", { days: 89 })], 7), [], NOW),
    ).toEqual({
      level: null,
      notice: null,
    });
    // No handshake this time: what was told stays.
    expect(certificateNotice(asset("a", "www.example.com", [], 14), [], NOW)).toEqual({
      level: 14,
      notice: null,
    });
  });

  it("sends one message for twelve names that share a certificate, naming all of them", () => {
    const names = Array.from({ length: 12 }, (_, i) => `host${String(i).padStart(2, "0")}.example.com`);
    const stored: NoticeAsset[] = names.map((value, i) =>
      asset(`a${i}`, value, [handshake("WILD", { days: 40 })]),
    );
    const sent: string[][] = [];
    for (const [i, value] of names.entries()) {
      const self = asset(`a${i}`, value, [handshake("WILD", { days: 12 })], stored[i]?.notifiedLevel ?? null);
      const result = certificateNotice(self, stored, NOW);
      // The worker stores the new snapshot and step together, so the next name sees them.
      stored[i] = { ...self, notifiedLevel: result.level };
      if (result.notice) sent.push(result.notice.names);
    }
    expect(sent).toEqual([names]);
    expect(stored.every((s) => s.notifiedLevel === 14)).toBe(true);
  });

  it("tells again for the next step once, whichever name gets there first", () => {
    const stored = [
      asset("a", "a.example.com", [handshake("WILD", { days: 12 })], 14),
      asset("b", "b.example.com", [handshake("WILD", { days: 12 })], 14),
    ];
    const b = certificateNotice(
      asset("b", "b.example.com", [handshake("WILD", { days: 6 })], 14),
      stored,
      NOW,
    );
    expect(b.notice).toMatchObject({ level: 7, names: ["a.example.com", "b.example.com"] });
    stored[1] = asset("b", "b.example.com", [handshake("WILD", { days: 6 })], b.level);
    const a = certificateNotice(
      asset("a", "a.example.com", [handshake("WILD", { days: 6 })], 14),
      stored,
      NOW,
    );
    expect(a).toEqual({ level: 7, notice: null });
  });

  it("does not count an announcement for another certificate, nor one of a less urgent step", () => {
    const others = [
      // Told at 30 days: not enough for the 14 day step.
      asset("b", "b.example.com", [handshake("WILD", { days: 20 })], 30),
      // Told at 14 days, but for its own certificate.
      asset("c", "c.example.com", [handshake("OTHER", { days: 12 })], 14),
    ];
    const result = certificateNotice(
      asset("a", "a.example.com", [handshake("WILD", { days: 12 })]),
      others,
      NOW,
    );
    expect(result.notice).toMatchObject({ level: 14, names: ["a.example.com", "b.example.com"] });
  });

  it("tells about an expired certificate once for all its names", () => {
    const stored = [asset("b", "b.example.com", [handshake("WILD", { days: -2 })], 0)];
    expect(
      certificateNotice(asset("a", "a.example.com", [handshake("WILD", { days: -2 })], 7), stored, NOW),
    ).toEqual({ level: 0, notice: null });
  });
});
