import type { Role } from "@garnetops/core";
import { queryOptions } from "@tanstack/svelte-query";
import { ApiError, api } from "./api.ts";
import { markSignedIn } from "./session-end.ts";

export interface Me {
  user: {
    id: string;
    name: string;
    email: string;
    /** Saved on the account; null follows this browser (ADR 0017). */
    locale: "en" | "de" | null;
    timeZone: string | null;
  };
  organization: {
    id: string;
    name: string;
    /** Nightly scan: local wall-clock time "HH:MM:SS" in an IANA zone (ADR 0005). */
    scanSchedule: { enabled: boolean; localTime: string; timeZone: string };
  };
  role: Role;
}

/** Where the current visitor stands; every route decides from this alone. */
export type Status =
  | { kind: "setup" }
  | { kind: "signed-out" }
  | { kind: "enroll" }
  | { kind: "no-organization" }
  | { kind: "ready"; me: Me };

async function loadStatus(): Promise<Status> {
  const setup = await api<{ needed: boolean }>("/setup");
  if (setup.needed) return { kind: "setup" };
  try {
    const me = await api<Me>("/me");
    markSignedIn();
    return { kind: "ready", me };
  } catch (error) {
    if (!(error instanceof ApiError)) throw error;
    if (error.status === 401) return { kind: "signed-out" };
    if (error.code === "mfa-enrollment-required") return { kind: "enroll" };
    if (error.status === 403) return { kind: "no-organization" };
    throw error;
  }
}

export const statusQuery = queryOptions({ queryKey: ["status"], queryFn: loadStatus, staleTime: 30_000 });

/** The page a visitor in this state belongs on. */
export function homeFor(status: Status): "/setup" | "/sign-in" | "/enroll" | "/no-access" | "/" {
  switch (status.kind) {
    case "setup":
      return "/setup";
    case "signed-out":
      return "/sign-in";
    case "enroll":
      return "/enroll";
    case "no-organization":
      return "/no-access";
    case "ready":
      return "/";
  }
}
