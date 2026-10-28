/**
 * Personal notifications (ADR 0019): which events exist, who is told, what a person has chosen,
 * and what a notification may contain. Pure logic shared by the API, the worker and the web app;
 * keep this file free of Node-only imports.
 *
 * A notification is a title key plus a few parameters and a relative link. It never carries free
 * text: the web app and the mail renderer turn the key into a sentence in the reader's language.
 */
import type { Role } from "./index.ts";

export const EVENT_GROUPS = ["code", "account", "system"] as const;
export type EventGroup = (typeof EVENT_GROUPS)[number];

export const USER_EVENTS = [
  "finding.new_critical",
  "gate.blocked",
  "scan.failed",
  "fix_pr.merged",
  "fix_pr.failed",
  "infra.certificate_changed",
  "team.invitation_accepted",
  "team.role_changed",
  "system.update_finished",
] as const;
export type UserEvent = (typeof USER_EVENTS)[number];

export const SCOPES = ["all", "mine"] as const;
export type Scope = (typeof SCOPES)[number];

export interface EventDefinition {
  group: EventGroup;
  /** The lowest role that is told. Nobody below it can receive or choose this event. */
  minRole: Role;
  /** Whether the person can limit it to what they added or requested ("mine"). */
  scoped: boolean;
  defaultScope: Scope;
  /** Also an event of the organisation channels (ADR 0010), so the same facts reach chat and mailboxes. */
  channelEvent: boolean;
  /** Only the person the event is about is told, whatever their role. */
  targeted?: boolean;
}

/** The catalogue. Order is the order of the rows in the settings matrix, per group. */
export const EVENT_CATALOG: Record<UserEvent, EventDefinition> = {
  "finding.new_critical": {
    group: "code",
    minRole: "viewer",
    scoped: true,
    defaultScope: "all",
    channelEvent: true,
  },
  "gate.blocked": { group: "code", minRole: "viewer", scoped: true, defaultScope: "all", channelEvent: true },
  "scan.failed": { group: "code", minRole: "member", scoped: true, defaultScope: "all", channelEvent: true },
  "fix_pr.merged": {
    group: "code",
    minRole: "member",
    scoped: true,
    defaultScope: "mine",
    channelEvent: false,
  },
  "fix_pr.failed": {
    group: "code",
    minRole: "member",
    scoped: true,
    defaultScope: "mine",
    channelEvent: false,
  },
  "infra.certificate_changed": {
    group: "account",
    minRole: "admin",
    scoped: false,
    defaultScope: "all",
    channelEvent: false,
  },
  "team.invitation_accepted": {
    group: "account",
    minRole: "admin",
    scoped: false,
    defaultScope: "all",
    channelEvent: false,
  },
  "team.role_changed": {
    group: "account",
    minRole: "viewer",
    scoped: false,
    defaultScope: "all",
    channelEvent: false,
    targeted: true,
  },
  "system.update_finished": {
    group: "system",
    minRole: "admin",
    scoped: false,
    defaultScope: "all",
    channelEvent: false,
  },
};

/** The sentence a notification shows; one per variant of an event. The texts live in the i18n files (`inapp.items`). */
export const TITLE_EVENTS = {
  findingNewCritical: "finding.new_critical",
  gateBlocked: "gate.blocked",
  scanFailed: "scan.failed",
  fixPrMerged: "fix_pr.merged",
  fixPrFailed: "fix_pr.failed",
  certificateChangedDirectory: "infra.certificate_changed",
  invitationAccepted: "team.invitation_accepted",
  roleChanged: "team.role_changed",
  updateSucceeded: "system.update_finished",
  updateFailed: "system.update_finished",
} as const satisfies Record<string, UserEvent>;
export type TitleKey = keyof typeof TITLE_EVENTS;

export const isTitleKey = (value: unknown): value is TitleKey =>
  typeof value === "string" && Object.hasOwn(TITLE_EVENTS, value);

/** Retention (ADR 0019): whichever limit is reached first. */
export const RETENTION = { maxPerUser: 500, days: 90 } as const;

/** At most one personal mail per person and event type in this time; more are sent as a digest. */
export const MAIL_MIN_INTERVAL_MS = 15 * 60_000;
/** A mail that could not be sent within this time is dropped (the notification stays in the app). */
export const MAIL_MAX_AGE_MS = 24 * 3600_000;

/** The PostgreSQL notification channel the API relays to the event streams of the signed-in people. */
export const USER_NOTIFICATION_CHANNEL = "user_notification";

/** What the channel's payload says: whose notification, which row. Nothing else travels in it. */
export interface UserNotificationNotice {
  u: string;
  id: number;
}

/* -------------------------------------------------------------------------- */
/* Contents                                                                    */
/* -------------------------------------------------------------------------- */

export type NotificationParams = Record<string, string | number>;

const MAX_PARAM_TEXT = 120;

/** Control characters, line and paragraph separators and bidirectional overrides become spaces. */
function replaceControl(text: string): string {
  let out = "";
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    const bad =
      code < 0x20 ||
      (code >= 0x7f && code <= 0x9f) ||
      code === 0x2028 ||
      code === 0x2029 ||
      (code >= 0x202a && code <= 0x202e) ||
      (code >= 0x2066 && code <= 0x2069);
    out += bad ? " " : char;
  }
  return out;
}
const PARAM_KEY = /^[a-zA-Z][a-zA-Z0-9]{0,23}$/;

/**
 * Parameters are short facts (names, counts, a version): numbers as they are, text without control
 * characters and cut at 120 characters. At most eight. Anything else is dropped.
 */
export function sanitizeParams(params: Record<string, unknown> | undefined): NotificationParams {
  const clean: NotificationParams = {};
  let count = 0;
  for (const [key, value] of Object.entries(params ?? {})) {
    if (count >= 8) break;
    if (!PARAM_KEY.test(key)) continue;
    if (typeof value === "number" && Number.isFinite(value)) clean[key] = value;
    else if (typeof value === "string") {
      const text = replaceControl(value);
      clean[key] = [...text.trim()].slice(0, MAX_PARAM_TEXT).join("");
    } else continue;
    count++;
  }
  return clean;
}

const LINK = /^\/(?!\/)[A-Za-z0-9\-._~!$&'()*+,;=:@%/?#]*$/;

/**
 * A link inside the app: a path with an optional query, nothing else. No scheme, no host, no
 * `//`, no backslash, no `..` segments, no control characters. The link is checked when it is
 * stored and again before the web app follows it.
 */
export function safeAppLink(link: unknown): string | null {
  if (typeof link !== "string" || link.length === 0 || link.length > 300) return null;
  if (!LINK.test(link)) return null;
  const path = link.split(/[?#]/, 1)[0] ?? "";
  if (path.split("/").some((segment) => segment === ".." || segment === ".")) return null;
  if (/%(?:2e|2f|5c|00)/i.test(path)) return null;
  return link;
}

/* -------------------------------------------------------------------------- */
/* Preferences and recipients                                                  */
/* -------------------------------------------------------------------------- */

export interface Preference {
  inApp: boolean;
  email: boolean;
  scope: Scope;
}

/** In app on, email off, the event's default scope (ADR 0019). */
export function defaultPreference(event: UserEvent): Preference {
  return { inApp: true, email: false, scope: EVENT_CATALOG[event].defaultScope };
}

/** What a person has stored over the defaults; a missing row or field means the default. */
export function resolvePreference(event: UserEvent, stored?: Partial<Preference> | null): Preference {
  const base = defaultPreference(event);
  const scope = stored?.scope && SCOPES.includes(stored.scope) ? stored.scope : base.scope;
  return {
    inApp: typeof stored?.inApp === "boolean" ? stored.inApp : base.inApp,
    email: typeof stored?.email === "boolean" ? stored.email : base.email,
    // Events that cannot be limited are never limited, whatever an old row says.
    scope: EVENT_CATALOG[event].scoped ? scope : "all",
  };
}

const ROLE_RANK: Record<Role, number> = { viewer: 0, member: 1, admin: 2, owner: 3 };

/** Whether this role is told about the event at all (and so sees its row in the matrix). */
export function roleReceives(role: Role, event: UserEvent): boolean {
  const definition = EVENT_CATALOG[event];
  return definition.targeted ? true : ROLE_RANK[role] >= ROLE_RANK[definition.minRole];
}

export interface Member {
  userId: string;
  role: Role;
}

/** The facts about the thing the event is about, used for the "only mine" scope and for targeted events. */
export interface EventContext {
  /** Who added the repository. */
  ownerUserId?: string | null;
  /** Who asked for the fix pull request. */
  requestedBy?: string | null;
  /** The person a targeted event is about. */
  targetUserId?: string | null;
}

export interface Recipient {
  userId: string;
  inApp: boolean;
  email: boolean;
}

/**
 * Who is told, and how. Role first (admin-only events never reach a member, whatever the
 * member's stored choices say), then the person's own choices, then the scope. Email only counts
 * when the organisation has a mail channel (`mailAvailable`).
 */
export function selectRecipients(input: {
  event: UserEvent;
  members: Member[];
  preferences: ReadonlyMap<string, Partial<Preference>>;
  context?: EventContext;
  mailAvailable: boolean;
}): Recipient[] {
  const definition = EVENT_CATALOG[input.event];
  const context = input.context ?? {};
  const recipients: Recipient[] = [];
  for (const member of input.members) {
    if (definition.targeted) {
      if (!context.targetUserId || member.userId !== context.targetUserId) continue;
    } else if (!roleReceives(member.role, input.event)) continue;
    const preference = resolvePreference(input.event, input.preferences.get(member.userId));
    if (definition.scoped && preference.scope === "mine") {
      const mine =
        (context.ownerUserId != null && context.ownerUserId === member.userId) ||
        (context.requestedBy != null && context.requestedBy === member.userId);
      if (!mine) continue;
    }
    const email = preference.email && input.mailAvailable;
    if (!preference.inApp && !email) continue;
    recipients.push({ userId: member.userId, inApp: preference.inApp, email });
  }
  return recipients;
}

/** Whether a stored matrix change is acceptable: nothing for events this role cannot receive. */
export function preferenceEvents(role: Role): UserEvent[] {
  return USER_EVENTS.filter((event) => roleReceives(role, event));
}
