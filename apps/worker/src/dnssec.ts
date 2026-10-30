/**
 * DNSSEC of a website's zone (ADR 0036): the DS records at the parent, the zone's DNSKEY records and the signatures over the keys and
 * over the SOA record, asked directly of the name servers (one query each, EDNS with the DO bit, TCP when an answer is truncated)
 * and checked here with node:crypto. Answers are hostile input: parsed by dns-packet, matched against the question asked, size-capped
 * by the protocol, and only numbers and dates leave this file.
 */
import { createHash, createPublicKey, type KeyObject, verify } from "node:crypto";
import { createSocket } from "node:dgram";
import { isIPv6, connect as tcpConnect } from "node:net";
import type { DnssecProblem, DnssecSnapshot } from "@garnetops/core/exposure";
import dnsPacket from "dns-packet";
import { type NetEnv, serverAddresses, zoneOf } from "./exposure-net.ts";

type RecordType = "DS" | "DNSKEY" | "SOA";

export interface DnskeyData {
  flags: number;
  algorithm: number;
  key: Buffer;
}
export interface DsData {
  keyTag: number;
  algorithm: number;
  digestType: number;
  digest: Buffer;
}
export interface RrsigData {
  typeCovered: string;
  algorithm: number;
  labels: number;
  originalTTL: number;
  expiration: number;
  inception: number;
  keyTag: number;
  signersName: string;
  signature: Buffer;
}
export interface SoaData {
  mname: string;
  rname: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  minimum: number;
}

/** The answer section of one query: the records of the type asked for and the signatures over them. */
export interface WireAnswer {
  records: unknown[];
  rrsigs: RrsigData[];
}
/** One query to one server; tests replace it. `undefined`: the server could not be asked. */
export type WireQuery = (server: string, name: string, type: RecordType) => Promise<WireAnswer | undefined>;

const TIMEOUT_MS = 3000;
/** The record codecs dns-packet exports but its type definitions leave out. */
type Codec = { encode(value: unknown): Buffer };
const codec = dnsPacket as unknown as { name: Codec; dnskey: Codec; soa: Codec; rrsig: Codec };
const lower = (name: string) => name.replace(/\.$/, "").toLowerCase();

/* -------------------------------------------------------------------------- */
/* Asking                                                                      */
/* -------------------------------------------------------------------------- */

function question(name: string, type: RecordType, id: number): Buffer {
  return dnsPacket.encode({
    type: "query",
    id,
    flags: 0,
    questions: [{ type, name, class: "IN" }],
    additionals: [{ type: "OPT", name: ".", udpPayloadSize: 1232, flags: dnsPacket.DNSSEC_OK }],
  } as dnsPacket.Packet);
}

/** The records of the answer that belong to the question; anything else in the packet is ignored. */
function answerOf(packet: dnsPacket.DecodedPacket, name: string, type: RecordType): WireAnswer {
  const records: unknown[] = [];
  const rrsigs: RrsigData[] = [];
  for (const rr of packet.answers ?? []) {
    if (lower(rr.name) !== lower(name)) continue;
    if (rr.type === type) records.push((rr as { data: unknown }).data);
    if (rr.type === "RRSIG" && (rr.data as RrsigData).typeCovered === type) rrsigs.push(rr.data as RrsigData);
  }
  return { records: records.slice(0, 50), rrsigs: rrsigs.slice(0, 50) };
}

function udpQuery(server: string, payload: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = createSocket(isIPv6(server) ? "udp6" : "udp4");
    const timer = setTimeout(() => done(new Error("timeout")), TIMEOUT_MS);
    const done = (error: Error | null, message?: Buffer) => {
      clearTimeout(timer);
      socket.close();
      if (error) reject(error);
      else resolve(message as Buffer);
    };
    socket.on("error", (error) => done(error));
    socket.on("message", (message) => done(null, message));
    socket.send(payload, 53, server);
  });
}

function tcpQuery(server: string, payload: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = tcpConnect({ host: server, port: 53 });
    const chunks: Buffer[] = [];
    let length = 0;
    const timer = setTimeout(() => socket.destroy(new Error("timeout")), TIMEOUT_MS);
    socket.on("connect", () => {
      const prefix = Buffer.alloc(2);
      prefix.writeUInt16BE(payload.length);
      socket.write(Buffer.concat([prefix, payload]));
    });
    socket.on("data", (chunk) => {
      chunks.push(chunk);
      length += chunk.length;
      const all = Buffer.concat(chunks, length);
      if (all.length >= 2 && all.length >= 2 + all.readUInt16BE(0)) {
        clearTimeout(timer);
        socket.end();
        resolve(all.subarray(2, 2 + all.readUInt16BE(0)));
      }
    });
    socket.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

/** One query over UDP, again over TCP when the answer was truncated. */
export const wireQuery: WireQuery = async (server, name, type) => {
  const id = Math.floor(Math.random() * 65536);
  const payload = question(name, type, id);
  try {
    let packet = dnsPacket.decode(await udpQuery(server, payload));
    if (packet.flag_tc) packet = dnsPacket.decode(await tcpQuery(server, payload));
    if (packet.id !== id || packet.type !== "response") return undefined;
    const asked = packet.questions?.[0];
    if (!asked || lower(asked.name) !== lower(name) || asked.type !== type) return undefined;
    // REFUSED, SERVFAIL and the like: this server cannot tell.
    const rcode = (packet as { rcode?: string }).rcode;
    if (rcode !== "NOERROR" && rcode !== "NXDOMAIN") return undefined;
    return answerOf(packet, name, type);
  } catch {
    return undefined;
  }
};

/* -------------------------------------------------------------------------- */
/* Checking (RFC 4034, 4509, 5702, 6605, 8080)                                 */
/* -------------------------------------------------------------------------- */

const nameWire = (name: string) => codec.name.encode(lower(name));
const withoutLength = (encoded: Buffer) => encoded.subarray(2);
export const dnskeyRdata = (k: DnskeyData) => withoutLength(codec.dnskey.encode(k));
const soaRdata = (s: SoaData) =>
  withoutLength(codec.soa.encode({ ...s, mname: lower(s.mname), rname: lower(s.rname) }));

/** RFC 4034 appendix B. */
export function keyTag(k: DnskeyData): number {
  const rdata = dnskeyRdata(k);
  let acc = 0;
  for (let i = 0; i < rdata.length; i++) acc += i & 1 ? (rdata[i] as number) : (rdata[i] as number) << 8;
  acc += (acc >> 16) & 0xffff;
  return acc & 0xffff;
}

const DIGESTS: Record<number, string> = { 1: "sha1", 2: "sha256", 4: "sha384" };

/** Whether a DS record names this key: tag, algorithm and the digest over the owner name and the key. */
export function dsMatches(ds: DsData, zone: string, key: DnskeyData): boolean {
  const hash = DIGESTS[ds.digestType];
  if (!hash || ds.algorithm !== key.algorithm || ds.keyTag !== keyTag(key)) return false;
  const digest = createHash(hash).update(nameWire(zone)).update(dnskeyRdata(key)).digest();
  return digest.equals(Buffer.from(ds.digest));
}

const b64u = (b: Buffer) => b.toString("base64url");

/** The public key of a DNSKEY record and how to verify with it; null for algorithms not checked here. */
function verifierOf(key: DnskeyData): { key: KeyObject; hash: string | null; ieee: boolean } | null {
  const raw = Buffer.from(key.key);
  try {
    switch (key.algorithm) {
      case 5:
      case 7:
      case 8:
      case 10: {
        // RFC 3110: exponent length (one byte, or zero and two bytes), exponent, modulus.
        let at = 1;
        let expLen = raw[0] as number;
        if (expLen === 0) {
          expLen = raw.readUInt16BE(1);
          at = 3;
        }
        const e = raw.subarray(at, at + expLen);
        const n = raw.subarray(at + expLen);
        const hash = key.algorithm === 8 ? "sha256" : key.algorithm === 10 ? "sha512" : "sha1";
        return {
          key: createPublicKey({ key: { kty: "RSA", n: b64u(n), e: b64u(e) }, format: "jwk" }),
          hash,
          ieee: false,
        };
      }
      case 13:
      case 14: {
        const size = key.algorithm === 13 ? 32 : 48;
        const crv = key.algorithm === 13 ? "P-256" : "P-384";
        const jwk = { kty: "EC", crv, x: b64u(raw.subarray(0, size)), y: b64u(raw.subarray(size, 2 * size)) };
        return {
          key: createPublicKey({ key: jwk, format: "jwk" }),
          hash: key.algorithm === 13 ? "sha256" : "sha384",
          ieee: true,
        };
      }
      case 15:
      case 16: {
        const crv = key.algorithm === 15 ? "Ed25519" : "Ed448";
        return {
          key: createPublicKey({ key: { kty: "OKP", crv, x: b64u(raw) }, format: "jwk" }),
          hash: null,
          ieee: false,
        };
      }
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/**
 * Whether a signature covers an RRset at `owner`: the RRSIG fields without the signature, then each record in canonical form
 * (lowercase owner, the original TTL, records sorted by their data). null: the algorithm is not checked here.
 */
export function signatureValid(
  sig: RrsigData,
  owner: string,
  type: "DNSKEY" | "SOA",
  rdatas: Buffer[],
  key: DnskeyData,
): boolean | null {
  const verifier = verifierOf(key);
  if (!verifier) return null;
  if (sig.algorithm !== key.algorithm || sig.keyTag !== keyTag(key)) return false;
  const head = withoutLength(
    codec.rrsig.encode({ ...sig, signersName: lower(sig.signersName), signature: Buffer.alloc(0) }),
  );
  const ownerWire = nameWire(owner);
  const fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(type === "DNSKEY" ? 48 : 6, 0);
  fixed.writeUInt16BE(1, 2);
  fixed.writeUInt32BE(sig.originalTTL >>> 0, 4);
  const records = [...rdatas].sort(Buffer.compare).map((rdata) => {
    const rr = Buffer.from(fixed);
    rr.writeUInt16BE(rdata.length, 8);
    return Buffer.concat([ownerWire, rr, rdata]);
  });
  const data = Buffer.concat([head, ...records]);
  try {
    return verify(
      verifier.hash,
      data,
      verifier.ieee ? { key: verifier.key, dsaEncoding: "ieee-p1363" } : verifier.key,
      Buffer.from(sig.signature),
    );
  } catch {
    return false;
  }
}

/** Everything the check needs, as the name servers answered. */
export interface DnssecInput {
  zone: string;
  ds: DsData[];
  keys: DnskeyData[];
  keySigs: RrsigData[];
  soa: SoaData | null;
  soaSigs: RrsigData[];
  now: Date;
}

const iso = (seconds: number) => new Date(seconds * 1000).toISOString();

/** The DNSSEC state of a zone from its records (pure, so it can be tested with known signatures). */
export function evaluateDnssec(input: DnssecInput): DnssecSnapshot {
  const { zone } = input;
  const now = Math.floor(input.now.getTime() / 1000);
  const keyRdatas = input.keys.map(dnskeyRdata);
  const keys = input.keys.map((k) => ({ keyTag: keyTag(k), algorithm: k.algorithm, flags: k.flags }));
  const ds = input.ds.map((d) => ({
    keyTag: d.keyTag,
    algorithm: d.algorithm,
    digestType: d.digestType,
    matches: input.keys.some((k) => dsMatches(d, zone, k)),
  }));
  const signatures: DnssecSnapshot["signatures"] = [];
  const check = (sig: RrsigData, type: "DNSKEY" | "SOA", rdatas: Buffer[], signers: DnskeyData[]) => {
    const signer = signers.find((k) => k.algorithm === sig.algorithm && keyTag(k) === sig.keyTag);
    const valid = signer ? signatureValid(sig, zone, type, rdatas, signer) : false;
    const timely = sig.inception <= now && now <= sig.expiration;
    signatures.push({
      covers: type,
      keyTag: sig.keyTag,
      algorithm: sig.algorithm,
      inception: iso(sig.inception),
      expiration: iso(sig.expiration),
      valid,
    });
    return { valid, timely, sig };
  };

  const zoneKeys = input.keys.filter((k) => (k.flags & 0x0100) !== 0);
  const trusted = input.keys.filter((k) => input.ds.some((d) => dsMatches(d, zone, k)));
  const keyChecks = input.keySigs.map((s) =>
    check(s, "DNSKEY", keyRdatas, input.ds.length > 0 ? trusted : zoneKeys),
  );
  const soaRdatas = input.soa ? [soaRdata(input.soa)] : [];
  const soaChecks = input.soaSigs.map((s) => check(s, "SOA", soaRdatas, zoneKeys));

  const snapshot = (
    state: DnssecSnapshot["state"],
    problem: DnssecProblem | null,
    used: RrsigData[] = [],
  ) => {
    const earliest = used.length > 0 ? Math.min(...used.map((s) => s.expiration)) : null;
    return {
      zone,
      state,
      problem,
      ds,
      keys,
      signatures: signatures.slice(0, 20),
      expiresAt: earliest === null ? null : iso(earliest),
    };
  };

  if (input.ds.length === 0 && input.keys.length === 0) return snapshot("unsigned", null);
  if (input.ds.length === 0) return snapshot("insecure", null);
  if (input.keys.length === 0) return snapshot("broken", "noDnskey");
  if (trusted.length === 0) return snapshot("broken", "dsNoMatch");

  // One good signature per step is enough; an algorithm not checked here does not count against the zone.
  const good = (checks: ReturnType<typeof check>[]) => checks.find((c) => c.valid !== false && c.timely);
  const why = (
    checks: ReturnType<typeof check>[],
    missing: DnssecProblem,
    invalid: DnssecProblem,
  ): DnssecProblem => {
    if (checks.length === 0) return missing;
    const valid = checks.filter((c) => c.valid !== false);
    if (valid.length === 0) return invalid;
    return valid.some((c) => c.sig.inception > now) && !valid.some((c) => c.sig.expiration < now)
      ? "signatureNotYetValid"
      : "signatureExpired";
  };
  const keyOk = good(keyChecks);
  if (!keyOk) return snapshot("broken", why(keyChecks, "dnskeyNotSigned", "dnskeySignatureInvalid"));
  const soaOk = good(soaChecks);
  if (!soaOk) return snapshot("broken", why(soaChecks, "soaNotSigned", "soaSignatureInvalid"));
  return snapshot("secure", null, [keyOk.sig, soaOk.sig]);
}

/* -------------------------------------------------------------------------- */
/* The check of one name                                                       */
/* -------------------------------------------------------------------------- */

/** Asks the first of the addresses that answers. */
async function askAny(query: WireQuery, addresses: string[], name: string, type: RecordType) {
  for (const address of addresses) {
    const answer = await query(address, name, type);
    if (answer) return answer;
  }
  return undefined;
}

/**
 * The DNSSEC state of the zone `name` lies in, from the zone's name servers (DNSKEY, SOA) and the parent's (DS). Only public
 * addresses are asked. "unknown" when the zone or its parent cannot be found or none of their servers answers.
 */
export async function readDnssec(
  env: NetEnv & { dnsWire?: WireQuery },
  name: string,
  now: Date,
): Promise<DnssecSnapshot | "unknown"> {
  const query = env.dnsWire ?? wireQuery;
  const zone = await zoneOf(env, name);
  if (!zone?.zone.includes(".")) return "unknown";
  const parentName = zone.zone.slice(zone.zone.indexOf(".") + 1);
  const parent = await zoneOf(env, parentName, true);
  if (!parent) return "unknown";
  const [own, above] = await Promise.all([
    serverAddresses(env, zone.servers, 2),
    serverAddresses(env, parent.servers, 2),
  ]);
  const [ds, keys, soa] = await Promise.all([
    askAny(query, above, zone.zone, "DS"),
    askAny(query, own, zone.zone, "DNSKEY"),
    askAny(query, own, zone.zone, "SOA"),
  ]);
  if (!ds || !keys || !soa) return "unknown";
  return evaluateDnssec({
    zone: zone.zone,
    ds: ds.records as DsData[],
    keys: keys.records as DnskeyData[],
    keySigs: keys.rrsigs,
    soa: (soa.records[0] as SoaData | undefined) ?? null,
    soaSigs: soa.rrsigs,
    now,
  });
}
