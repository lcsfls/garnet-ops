/**
 * The agent enrollment helper (ADR 0015): the official Wazuh agent installation commands with
 * the customer's manager address filled in. GarnetOps does not build, package, sign or ship an
 * agent; it only prints what the Wazuh documentation says (https://packages.wazuh.com), for the
 * version of the customer's own manager. The customer installs and runs Wazuh (GPL-2.0) on their
 * own machines; nothing of it is part of GarnetOps.
 *
 * Everything that ends up in a command is validated against a whitelist of characters first and
 * quoted for the target shell as well. An enrollment password is never an input: when the manager
 * asks for one, the command carries a marked placeholder that the admin replaces on the host.
 *
 * The templates are versioned: change a template, raise ENROLLMENT_TEMPLATES_VERSION.
 */
import { checkEnrollmentHost, type WazuhVersion } from "./wazuh.ts";

export const ENROLLMENT_TEMPLATES_VERSION = 1;

export const ENROLL_OS = ["debian", "rhel", "suse", "windows", "macos"] as const;
export type EnrollOs = (typeof ENROLL_OS)[number];
export const ENROLL_ARCH = ["amd64", "arm64"] as const;
export type EnrollArch = (typeof ENROLL_ARCH)[number];

/** What the admin must replace on the host. Written in capitals between angle brackets so it cannot be missed. */
export const PASSWORD_PLACEHOLDER = "<ENROLLMENT_PASSWORD>";

export type EnrollProblem = "manager" | "group" | "name" | "version" | "os" | "arch";

export interface EnrollInput {
  os: string;
  arch: string;
  /** The address agents use to reach the manager (`WAZUH_MANAGER`). */
  manager: string;
  /** The manager's version, as detected by the last sync. */
  version: WazuhVersion;
  /** Optional comma-separated agent group(s); a group that does not exist is created by Wazuh on enrollment. */
  group?: string | undefined;
  /** Optional name of the agent; Wazuh uses the host name when it is left out. */
  name?: string | undefined;
  /** The manager asks for an enrollment password: the command gets a placeholder for it. */
  password?: boolean | undefined;
}

export interface EnrollStep {
  id: "trust" | "repository" | "install" | "start";
  shell: "bash" | "powershell";
  text: string;
}

export type EnrollResult =
  | {
      ok: true;
      templatesVersion: number;
      os: EnrollOs;
      arch: EnrollArch;
      /** The package version the commands pin: an agent must not be newer than its manager. */
      packageVersion: string | null;
      /** The repository line of the Wazuh documentation ("4.x", "5.x"). */
      series: string;
      /** The 5.x commands follow the documentation of the release candidates (ADR 0002). */
      preview: boolean;
      /** The command carries a placeholder for the enrollment password. */
      passwordPlaceholder: boolean;
      steps: EnrollStep[];
    }
  | { ok: false; problem: EnrollProblem };

const WORD = /^[A-Za-z0-9._-]{1,128}$/;

/** Comma-separated group names, each a plain word; at most five. */
export function checkAgentGroups(value: string): string | null {
  const parts = value.split(",").map((p) => p.trim());
  if (parts.length === 0 || parts.length > 5 || parts.some((p) => !WORD.test(p))) return null;
  return parts.join(",");
}

export function checkAgentName(value: string): string | null {
  const name = value.trim();
  return WORD.test(name) ? name : null;
}

/** Quotes a value for a POSIX shell: single quotes, a single quote inside becomes `'\''`. */
export function posixQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

/** Quotes a value for PowerShell: single quotes, a single quote inside is doubled. */
export function powershellQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

const KEY_URL = "https://packages.wazuh.com/key/GPG-KEY-WAZUH";

/** `4.12.0` out of a version, or null when the patch level is not known (then nothing is pinned). */
function packageVersionOf(version: WazuhVersion): string | null {
  return /^\d+\.\d+\.\d+$/.test(version.version) ? version.version : null;
}

export function buildEnrollment(input: EnrollInput): EnrollResult {
  const os = (ENROLL_OS as readonly string[]).includes(input.os) ? (input.os as EnrollOs) : null;
  if (!os) return { ok: false, problem: "os" };
  const arch = (ENROLL_ARCH as readonly string[]).includes(input.arch) ? (input.arch as EnrollArch) : null;
  if (!arch) return { ok: false, problem: "arch" };
  const manager = checkEnrollmentHost(input.manager);
  if (!manager.ok) return { ok: false, problem: "manager" };
  const group = input.group ? checkAgentGroups(input.group) : undefined;
  if (input.group && !group) return { ok: false, problem: "group" };
  const name = input.name ? checkAgentName(input.name) : undefined;
  if (input.name && !name) return { ok: false, problem: "name" };
  if (input.version.major !== 4 && input.version.major !== 5) return { ok: false, problem: "version" };

  const series = `${input.version.major}.x`;
  const pinned = packageVersionOf(input.version);
  const password = input.password === true;

  // The environment variables the Wazuh installer reads, in the order of its documentation.
  const variables: [string, string][] = [["WAZUH_MANAGER", manager.value]];
  if (group) variables.push(["WAZUH_AGENT_GROUP", group]);
  if (name) variables.push(["WAZUH_AGENT_NAME", name]);
  if (password) variables.push(["WAZUH_REGISTRATION_PASSWORD", PASSWORD_PLACEHOLDER]);
  const posix = variables.map(([k, v]) => `${k}=${posixQuote(v)}`);
  const msi = variables.map(([k, v]) => `${k}=${powershellQuote(v)}`);

  const steps: EnrollStep[] = [];
  const bash = (id: EnrollStep["id"], lines: string[]) =>
    steps.push({ id, shell: "bash", text: lines.join("\n") });

  const rpmRepository = [
    "cat > REPOFILE << 'EOF'",
    "[wazuh]",
    "gpgcheck=1",
    `gpgkey=${KEY_URL}`,
    "enabled=1",
    "name=EL-$releasever - Wazuh",
    `baseurl=https://packages.wazuh.com/${series}/yum/`,
    "protect=1",
    "EOF",
  ];

  switch (os) {
    case "debian":
      bash("trust", [
        `curl -s ${KEY_URL} | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg`,
      ]);
      bash("repository", [
        `echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/${series}/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list`,
        "apt-get update",
      ]);
      bash("install", [`${posix.join(" ")} apt-get install wazuh-agent${pinned ? `=${pinned}-1` : ""}`]);
      bash("start", [
        "systemctl daemon-reload",
        "systemctl enable wazuh-agent",
        "systemctl start wazuh-agent",
      ]);
      break;
    case "rhel":
      bash("trust", [`rpm --import ${KEY_URL}`]);
      bash(
        "repository",
        rpmRepository.map((l) => l.replace("REPOFILE", "/etc/yum.repos.d/wazuh.repo")),
      );
      bash("install", [`${posix.join(" ")} yum install wazuh-agent${pinned ? `-${pinned}-1` : ""}`]);
      bash("start", [
        "systemctl daemon-reload",
        "systemctl enable wazuh-agent",
        "systemctl start wazuh-agent",
      ]);
      break;
    case "suse":
      bash("trust", [`rpm --import ${KEY_URL}`]);
      bash(
        "repository",
        rpmRepository.map((l) => l.replace("REPOFILE", "/etc/zypp/repos.d/wazuh.repo")),
      );
      bash("install", [`${posix.join(" ")} zypper install wazuh-agent${pinned ? `-${pinned}-1` : ""}`]);
      bash("start", [
        "systemctl daemon-reload",
        "systemctl enable wazuh-agent",
        "systemctl start wazuh-agent",
      ]);
      break;
    case "windows": {
      const file = `wazuh-agent-${pinned ?? input.version.version}-1.msi`;
      steps.push({
        id: "install",
        shell: "powershell",
        text: [
          `Invoke-WebRequest -Uri https://packages.wazuh.com/${series}/windows/${file} -OutFile \${env:tmp}\\wazuh-agent.msi`,
          `msiexec.exe /i \${env:tmp}\\wazuh-agent.msi /q ${msi.join(" ")}`,
        ].join("\n"),
      });
      steps.push({ id: "start", shell: "powershell", text: "NET START WazuhSvc" });
      break;
    }
    case "macos": {
      const file = `wazuh-agent-${pinned ?? input.version.version}-1.${arch === "arm64" ? "arm64" : "intel64"}.pkg`;
      bash("install", [
        `curl -so wazuh-agent.pkg https://packages.wazuh.com/${series}/macos/${file} && echo "${posix.join(" && ")}" > /tmp/wazuh_envs && sudo installer -pkg ./wazuh-agent.pkg -target /`,
      ]);
      bash("start", ["sudo /Library/Ossec/bin/wazuh-control start"]);
      break;
    }
  }

  return {
    ok: true,
    templatesVersion: ENROLLMENT_TEMPLATES_VERSION,
    os,
    arch,
    packageVersion: pinned,
    series,
    preview: input.version.major === 5,
    passwordPlaceholder: password,
    steps,
  };
}
