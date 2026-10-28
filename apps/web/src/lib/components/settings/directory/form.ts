import {
  DIRECTORY_LIMITS,
  DIRECTORY_PRESET_VALUES,
  type DirectoryPreset,
  type GROUP_MODES,
  type GroupRole,
} from "@garnetops/core/directory";
import type { DirectorySettings } from "../../../directory.ts";
import type { MessageKey } from "../../../i18n.svelte.ts";

export const PRESET_LABELS = {
  "active-directory": "directory.presets.active-directory",
  openldap: "directory.presets.openldap",
  custom: "directory.presets.custom",
} as const satisfies Record<DirectoryPreset, MessageKey>;
export const MODE_LABELS = {
  "member-of": "directory.groupModes.member-of",
  nested: "directory.groupModes.nested",
  search: "directory.groupModes.search",
} as const satisfies Record<(typeof GROUP_MODES)[number], MessageKey>;
export const MODE_HINTS = {
  "member-of": "directory.groupModeHints.member-of",
  nested: "directory.groupModeHints.nested",
  search: "directory.groupModeHints.search",
} as const satisfies Record<(typeof GROUP_MODES)[number], MessageKey>;

export interface FormState {
  enabled: boolean;
  preset: DirectoryPreset;
  /** One URL per line. */
  servers: string;
  tlsTrust: DirectorySettings["tlsTrust"];
  caCertificate: string;
  bindDn: string;
  bindPassword: string;
  userBaseDn: string;
  userFilter: string;
  emailAttribute: string;
  nameAttribute: string;
  uniqueIdAttribute: string;
  groupMode: DirectorySettings["groupMode"];
  groupFilter: string;
  groupRoles: GroupRole[];
  emailVerified: boolean;
  // Number inputs bound with bind:value hold numbers once edited; bodyOf converts with Number() either way.
  connectTimeoutSeconds: string | number;
  operationTimeoutSeconds: string | number;
  sizeLimit: string | number;
}

export const initialState = (settings: DirectorySettings | null): FormState => {
  if (!settings) {
    return {
      enabled: false,
      preset: "active-directory",
      servers: "",
      tlsTrust: "system",
      caCertificate: "",
      bindDn: "",
      bindPassword: "",
      userBaseDn: "",
      ...DIRECTORY_PRESET_VALUES["active-directory"],
      groupRoles: [{ dn: "", role: "member" }],
      emailVerified: false,
      connectTimeoutSeconds: String(DIRECTORY_LIMITS.connectTimeoutSeconds.default),
      operationTimeoutSeconds: String(DIRECTORY_LIMITS.operationTimeoutSeconds.default),
      sizeLimit: String(DIRECTORY_LIMITS.sizeLimit.default),
    };
  }
  return {
    enabled: settings.enabled,
    preset: settings.preset,
    servers: settings.servers.join("\n"),
    tlsTrust: settings.tlsTrust,
    caCertificate: settings.caCertificate,
    bindDn: settings.bindDn,
    bindPassword: "",
    userBaseDn: settings.userBaseDn,
    userFilter: settings.userFilter,
    emailAttribute: settings.emailAttribute,
    nameAttribute: settings.nameAttribute,
    uniqueIdAttribute: settings.uniqueIdAttribute,
    groupMode: settings.groupMode,
    groupFilter: settings.groupFilter,
    groupRoles: settings.groupRoles.length > 0 ? settings.groupRoles : [{ dn: "", role: "member" }],
    emailVerified: settings.emailVerified,
    connectTimeoutSeconds: String(settings.connectTimeoutSeconds),
    operationTimeoutSeconds: String(settings.operationTimeoutSeconds),
    sizeLimit: String(settings.sizeLimit),
  };
};

/** The request body for a form state. The password is sent only when something was typed. */
export function bodyOf(form: FormState): Record<string, unknown> {
  return {
    enabled: form.enabled,
    preset: form.preset,
    servers: form.servers
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean),
    tlsTrust: form.tlsTrust,
    caCertificate: form.caCertificate,
    bindDn: form.bindDn,
    ...(form.bindPassword ? { bindPassword: form.bindPassword } : {}),
    userBaseDn: form.userBaseDn,
    userFilter: form.userFilter,
    emailAttribute: form.emailAttribute,
    nameAttribute: form.nameAttribute,
    uniqueIdAttribute: form.uniqueIdAttribute,
    groupMode: form.groupMode,
    groupFilter: form.groupFilter,
    groupRoles: form.groupRoles.filter((g) => g.dn.trim() !== ""),
    emailVerified: form.emailVerified,
    connectTimeoutSeconds: Number(form.connectTimeoutSeconds),
    operationTimeoutSeconds: Number(form.operationTimeoutSeconds),
    sizeLimit: Number(form.sizeLimit),
  };
}
