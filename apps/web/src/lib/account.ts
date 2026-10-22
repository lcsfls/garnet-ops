import { queryOptions } from "@tanstack/react-query";
import { api } from "./api.ts";

export interface PasskeyRow {
  id: string;
  name: string | null;
  createdAt: string | null;
  lastUsedAt: string | null;
  deviceType: string;
  backedUp: boolean;
}

export interface AccountOverview {
  profile: {
    name: string;
    email: string;
    locale: "en" | "de" | null;
    timeZone: string | null;
    createdAt: string;
  };
  secondFactor: {
    totp: { enrolled: boolean; backupCodesRemaining: number };
    passkeys: PasskeyRow[];
    /** False when the public URL cannot carry passkeys (an IP address or plain http). */
    passkeysAvailable: boolean;
    /** The domain the passkeys are bound to. */
    relyingParty: string;
  };
}

export interface SessionRow {
  id: string;
  current: boolean;
  createdAt: string;
  lastActiveAt: string;
  expiresAt: string;
  ip: string | null;
  device: { browser: string; os: string };
}

export const accountQuery = queryOptions({
  queryKey: ["account"],
  queryFn: () => api<AccountOverview>("/account"),
});

export const sessionsQuery = queryOptions({
  queryKey: ["account", "sessions"],
  queryFn: () => api<SessionRow[]>("/account/sessions"),
});
