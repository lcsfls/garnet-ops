/**
 * Types and helpers of the directory sign-in screens (ADR 0020): the settings under Settings,
 * Sign-in, the sign-in page and the Team page.
 */
import type {
  DirectoryGroupMode,
  DirectoryPreset,
  DirectoryProblem,
  DirectoryRole,
  DirectoryTlsTrust,
  GroupRole,
} from "@garnetops/core/directory";
import { queryOptions } from "@tanstack/svelte-query";
import { api } from "./api.ts";

export interface DirectorySettings {
  enabled: boolean;
  preset: DirectoryPreset;
  servers: string[];
  tlsTrust: DirectoryTlsTrust;
  caCertificate: string;
  bindDn: string;
  bindPasswordSet: boolean;
  userBaseDn: string;
  userFilter: string;
  emailAttribute: string;
  nameAttribute: string;
  uniqueIdAttribute: string;
  groupMode: DirectoryGroupMode;
  groupFilter: string;
  groupRoles: GroupRole[];
  emailVerified: boolean;
  connectTimeoutSeconds: number;
  operationTimeoutSeconds: number;
  sizeLimit: number;
}

export interface PinFacts {
  fingerprint: string;
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
}

export interface DirectoryServerView {
  url: string;
  transport: "ldaps" | "starttls";
  /** Null unless pinning is switched on. */
  certificate: {
    status: "pending" | "confirmed" | "changed";
    pin: (PinFacts & { confirmedAt: string }) | null;
    candidate: (PinFacts & { trusted: boolean; seenAt: string }) | null;
  } | null;
}

export interface DirectoryView {
  configured: boolean;
  settings: DirectorySettings | null;
  servers: DirectoryServerView[];
  testedAt: string | null;
  bindBlockedUntil: string | null;
  /** Accounts that come from the directory. */
  accounts: number;
  /** True when the last save switched the sign-in off because of the change. */
  switchedOff?: boolean;
}

export const directoryQuery = queryOptions({
  queryKey: ["directory"],
  queryFn: () => api<DirectoryView>("/directory"),
});

export interface DirectoryUserView {
  uniqueId: string;
  dn: string;
  email: string | null;
  name: string | null;
  groups: string[];
  role: DirectoryRole | null;
}

export interface TestView {
  ok: boolean;
  problem?: DirectoryProblem;
  servers: {
    url: string;
    ok: boolean;
    problem?: DirectoryProblem;
    detail?: string;
    transport: "ldaps" | "starttls";
    certificate?: {
      fingerprint: string;
      subject: string;
      issuer: string;
      validFrom: string;
      validTo: string;
      trusted: boolean;
    };
  }[];
  user?: DirectoryUserView;
  groups?: { dn: string; exists: boolean; member: boolean }[];
  latencyMs: number;
}

/** The sign-in page asks, before anyone is signed in, whether it may offer the directory. */
export const signInOptionsQuery = queryOptions({
  queryKey: ["sign-in-options"],
  queryFn: () => api<{ directory: boolean }>("/sign-in-options"),
  staleTime: 30_000,
});
