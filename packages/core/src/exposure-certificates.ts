/**
 * Certificates of website monitoring, grouped by certificate rather than by name (ADR 0023; the amendment of ADR 0033).
 *
 * One wildcard or multi-name certificate is often served on many names. Stage 1 keeps its findings per asset (they belong to the
 * report and the gates of each asset and never change meaning), but the certificates view and the expiry notification look at the
 * certificate itself: one row and one message per certificate and warning step, whatever the number of names that serve it.
 *
 * Pure logic shared by the API, the worker and the web app; keep this file free of Node-only imports. Snapshots come from the
 * database as JSON written by earlier versions too, so everything here reads them defensively.
 */
import { type CertInfo, daysToExpiry, type ExpiryLevel, expiryLevel, expiryWarningDue } from "./exposure.ts";

/* -------------------------------------------------------------------------- */
/* Names and wildcards                                                         */
/* -------------------------------------------------------------------------- */

/** A subject alternative name as a lower-case DNS name without the `DNS:` prefix, or null for an address or anything else. */
export function sanDnsName(san: string): string | null {
  const text = san.trim();
  if (/^IP( Address)?:/i.test(text)) return null;
  const name = text.replace(/^DNS:/i, "").trim().toLowerCase().replace(/\.$/, "");
  if (name.length === 0 || /[\s:/]/.test(name)) return null;
  return name;
}

/** Whether a name is a wildcard (`*.example.com`). */
export const isWildcardName = (name: string): boolean => name.startsWith("*.");

/** The DNS names of a certificate's alternative names, wildcards included. */
export const certificateDnsNames = (sans: readonly string[]): string[] =>
  sans.flatMap((san) => {
    const name = sanDnsName(san);
    return name ? [name] : [];
  });

/**
 * Whether a certificate name covers a host name the way browsers check it (RFC 6125, section 6.4.3, without partial labels): an
 * exact match, or a wildcard in the leftmost label that stands for exactly one label.
 */
export function nameCovers(certificateName: string, host: string): boolean {
  const name = certificateName.toLowerCase();
  const target = host.toLowerCase().replace(/\.$/, "");
  if (!isWildcardName(name)) return name === target;
  const base = name.slice(2);
  if (!target.endsWith(`.${base}`)) return false;
  const label = target.slice(0, -(base.length + 1));
  return label.length > 0 && !label.includes(".");
}

/** Why a wildcard on the certificate does not cover a name: the name is the domain itself, or more than one level below it. */
export interface WildcardMiss {
  wildcard: string;
  reason: "apex" | "deeper";
}

/**
 * The wildcard of a certificate that looks as if it should cover `host` but does not: `*.example.com` does not cover the domain
 * `example.com` itself, nor `a.b.example.com` two levels below. Null when a name of the certificate covers the host, or when no
 * wildcard is near it. The name check of stage 1 already refuses such a certificate; this only says why.
 */
export function wildcardMiss(host: string, sans: readonly string[]): WildcardMiss | null {
  const target = host.toLowerCase().replace(/\.$/, "");
  const names = certificateDnsNames(sans);
  if (names.some((name) => nameCovers(name, target))) return null;
  for (const name of names) {
    if (!isWildcardName(name)) continue;
    const base = name.slice(2);
    if (target === base) return { wildcard: name, reason: "apex" };
    if (target.endsWith(`.${base}`)) return { wildcard: name, reason: "deeper" };
  }
  return null;
}

/* -------------------------------------------------------------------------- */
/* Reading snapshots                                                           */
/* -------------------------------------------------------------------------- */

const record = (v: unknown): Record<string, unknown> | null =>
  typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
const bool = (v: unknown): boolean | null => (typeof v === "boolean" ? v : null);
const validDate = (v: unknown): string | null => {
  const text = str(v);
  return text && Number.isFinite(new Date(text).getTime()) ? text : null;
};

/** One certificate as one handshake of a snapshot presented it. */
export interface ServedCertificate {
  address: string;
  port: number;
  cert: CertInfo;
  trusted: boolean | null;
  nameMatches: boolean | null;
}

/**
 * The certificates the TLS handshakes of a snapshot saw (`passive.tls`), skipping handshakes without a certificate and entries
 * that lack the fields a certificate needs (older or hand-made snapshots).
 */
export function servedCertificates(tls: unknown): ServedCertificate[] {
  if (!Array.isArray(tls)) return [];
  return tls.flatMap((entry) => {
    const t = record(entry);
    const c = record(t?.cert);
    if (!t || !c) return [];
    const fingerprint = str(c.fingerprint);
    const validTo = validDate(c.validTo);
    if (!fingerprint || !validTo) return [];
    const cert: CertInfo = {
      subject: str(c.subject) ?? "",
      issuer: str(c.issuer) ?? "",
      sans: Array.isArray(c.sans) ? c.sans.filter((s): s is string => typeof s === "string") : [],
      validFrom: validDate(c.validFrom) ?? validTo,
      validTo,
      fingerprint,
      keyType: str(c.keyType),
      keyBits: typeof c.keyBits === "number" && Number.isFinite(c.keyBits) ? c.keyBits : null,
      selfSigned: c.selfSigned === true,
    };
    return [
      {
        address: str(t.address) ?? "",
        port: typeof t.port === "number" ? t.port : 443,
        cert,
        trusted: bool(t.trusted),
        nameMatches: bool(t.nameMatches),
      },
    ];
  });
}

/** The certificate of a snapshot that expires first, with its days left; null when no certificate was seen. */
export function soonestCertificate(
  tls: unknown,
  now: Date,
): { fingerprint: string; validTo: string; days: number } | null {
  let best: { fingerprint: string; validTo: string; days: number } | null = null;
  for (const served of servedCertificates(tls)) {
    const days = daysToExpiry(served.cert.validTo, now);
    if (!best || days < best.days)
      best = { fingerprint: served.cert.fingerprint, validTo: served.cert.validTo, days };
  }
  return best;
}

/* -------------------------------------------------------------------------- */
/* Grouping                                                                    */
/* -------------------------------------------------------------------------- */

/** What the grouping needs of an asset: its name and the TLS handshakes of its latest stage 1 look. */
export interface CertificateSource {
  id: string;
  value: string;
  /** `passive.tls` as stored; anything else counts as no handshake. */
  tls: unknown;
}

/** One asset that served a certificate in its latest look. */
export interface CertificateServer {
  id: string;
  value: string;
  /** The addresses that presented this certificate for the asset. */
  addresses: string[];
  /** Whether the name check of the handshake passed; null when no name was checked (an address). */
  nameMatches: boolean | null;
  trusted: boolean | null;
  /** Why a wildcard on the certificate does not cover this name, if that is the reason the name check failed. */
  wildcardMiss: WildcardMiss | null;
}

/** One certificate (by SHA-256 fingerprint) and every asset that served it. */
export interface CertificateGroup {
  fingerprint: string;
  subject: string;
  issuer: string;
  sans: string[];
  /** The wildcard names among the alternative names (`*.example.com`). */
  wildcards: string[];
  validFrom: string;
  validTo: string;
  /** Whole days left; negative once expired. */
  days: number;
  /** The warning step it is in (30, 14, 7, 0 for expired); null while more than 30 days are left. */
  level: ExpiryLevel | null;
  keyType: string | null;
  keyBits: number | null;
  selfSigned: boolean;
  /** Sorted by name. */
  assets: CertificateServer[];
}

/**
 * Groups the certificates of the latest stage 1 looks by fingerprint: one entry per certificate with the assets that served it,
 * the soonest expiry first. An asset that served one certificate on several addresses appears once, with those addresses.
 */
export function groupCertificates(sources: readonly CertificateSource[], now: Date): CertificateGroup[] {
  const groups = new Map<string, CertificateGroup>();
  for (const source of sources) {
    for (const served of servedCertificates(source.tls)) {
      const cert = served.cert;
      let group = groups.get(cert.fingerprint);
      if (!group) {
        const days = daysToExpiry(cert.validTo, now);
        group = {
          fingerprint: cert.fingerprint,
          subject: cert.subject,
          issuer: cert.issuer,
          sans: cert.sans,
          wildcards: certificateDnsNames(cert.sans).filter(isWildcardName),
          validFrom: cert.validFrom,
          validTo: cert.validTo,
          days,
          level: expiryLevel(days),
          keyType: cert.keyType,
          keyBits: cert.keyBits,
          selfSigned: cert.selfSigned,
          assets: [],
        };
        groups.set(cert.fingerprint, group);
      }
      const known = group.assets.find((x) => x.id === source.id);
      if (known) {
        if (served.address && !known.addresses.includes(served.address)) known.addresses.push(served.address);
        // A failed name check on any address counts.
        if (served.nameMatches === false) known.nameMatches = false;
        if (served.trusted === false) known.trusted = false;
        continue;
      }
      group.assets.push({
        id: source.id,
        value: source.value,
        addresses: served.address ? [served.address] : [],
        nameMatches: served.nameMatches,
        trusted: served.trusted,
        wildcardMiss: served.nameMatches === false ? wildcardMiss(source.value, cert.sans) : null,
      });
    }
  }
  const list = [...groups.values()];
  for (const group of list)
    group.assets.sort((x, y) => x.value.localeCompare(y.value) || x.id.localeCompare(y.id));
  return list.sort(
    (x, y) => x.validTo.localeCompare(y.validTo) || x.fingerprint.localeCompare(y.fingerprint),
  );
}

/**
 * For one asset: the other assets that served each of its certificates in their latest look. Feeds "this certificate is also served
 * on N other names" in the TLS section of a website.
 */
export function sharedCertificates(
  assetId: string,
  sources: readonly CertificateSource[],
  now: Date,
): { fingerprint: string; others: { id: string; value: string }[] }[] {
  return groupCertificates(sources, now)
    .filter((group) => group.assets.some((x) => x.id === assetId))
    .map((group) => ({
      fingerprint: group.fingerprint,
      others: group.assets.filter((x) => x.id !== assetId).map((x) => ({ id: x.id, value: x.value })),
    }));
}

/* -------------------------------------------------------------------------- */
/* Expiry notifications, once per certificate and step                         */
/* -------------------------------------------------------------------------- */

/** An asset as the expiry notification sees it: its latest TLS handshakes and the warning step last announced for it. */
export interface NoticeAsset {
  id: string;
  value: string;
  /** `exposure_asset.cert_notified_level`: the step told for this asset's soonest certificate, null for none. */
  notifiedLevel: number | null;
  tls: unknown;
}

export interface CertificateNotice {
  fingerprint: string;
  level: ExpiryLevel;
  days: number;
  /** Every asset name that served the certificate in its latest look (this one included), sorted. */
  names: string[];
}

/**
 * Decides the expiry warning of one asset after a stage 1 look (ADR 0023, section 8): once per step (30, 14, 7 days, expired),
 * again after a renewal, and **once per certificate**: when another asset whose soonest certificate is the same one already
 * announced this step (or a more urgent one), nothing is sent again. `level` is what to store for the asset either way, so the
 * names that share a certificate keep the same state.
 *
 * `asset.tls` is the new snapshot; `others` are the other assets of the organisation as stored.
 */
export function certificateNotice(
  asset: NoticeAsset,
  others: readonly NoticeAsset[],
  now: Date,
): { level: number | null; notice: CertificateNotice | null } {
  const soonest = soonestCertificate(asset.tls, now);
  // No certificate seen this time: keep what was announced, as before.
  if (!soonest) return { level: asset.notifiedLevel, notice: null };
  const level = expiryLevel(soonest.days);
  if (level === null || !expiryWarningDue(level, asset.notifiedLevel)) return { level, notice: null };
  const peers = others.filter((other) => other.id !== asset.id);
  const told = peers.some(
    (other) =>
      other.notifiedLevel !== null &&
      other.notifiedLevel <= level &&
      soonestCertificate(other.tls, now)?.fingerprint === soonest.fingerprint,
  );
  if (told) return { level, notice: null };
  const names = new Set([asset.value]);
  for (const other of peers) {
    if (servedCertificates(other.tls).some((s) => s.cert.fingerprint === soonest.fingerprint))
      names.add(other.value);
  }
  return {
    level,
    notice: {
      fingerprint: soonest.fingerprint,
      level,
      days: soonest.days,
      names: [...names].sort((x, y) => x.localeCompare(y)),
    },
  };
}
