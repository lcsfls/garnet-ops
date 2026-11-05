/**
 * The host agent's installation (ADR 0037): this installation serves the agent binaries it was built with and a script that
 * installs one of them as a hardened systemd service or, on hosts with OpenRC (Alpine), as an unprivileged OpenRC service. Nothing
 * comes from the internet, so it works air-gapped, and the version always matches the server.
 */
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

export const AGENT_ARCHES = ["amd64", "arm64"] as const;
export type AgentArch = (typeof AGENT_ARCHES)[number];
export const agentBinaryName = (arch: AgentArch) => `garnetops-agent-linux-${arch}`;

/** The bytes and SHA-256 of each built binary, read once; null for an arch this installation was not built with. */
const cache = new Map<string, Promise<{ bytes: Buffer; sha256: string } | null>>();
export function agentBinary(dir: string, arch: AgentArch) {
  const key = `${dir}:${arch}`;
  let entry = cache.get(key);
  if (!entry) {
    entry = readFile(join(dir, agentBinaryName(arch))).then(
      (bytes) => ({ bytes, sha256: createHash("sha256").update(bytes).digest("hex") }),
      () => null,
    );
    cache.set(key, entry);
  }
  return entry;
}

/** The systemd unit: an unprivileged user, a read-only system, no capabilities, and limits on memory and CPU. */
export const SYSTEMD_UNIT = `[Unit]
Description=GarnetOps host agent
Documentation=https://github.com/lcsfls/garnet-ops/blob/main/docs/hosts.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=garnetops-agent
Group=garnetops-agent
EnvironmentFile=/etc/garnetops-agent/agent.env
ExecStart=/usr/local/bin/garnetops-agent run
Restart=on-failure
RestartSec=60
StateDirectory=garnetops-agent
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
MemoryMax=256M
CPUQuota=20%

[Install]
WantedBy=multi-user.target
`;

/**
 * The unit's settings that need namespaces or seccomp from the container manager. In a container (an unprivileged Proxmox VE
 * container without "nesting", for example) systemd may be unable to set them up and the service would fail to start with
 * 226/NAMESPACE; the script tries them with a short transient service first and stops with a clear message. The unit is never
 * weakened to fit.
 */
export const SANDBOX_CHECK = [
  "NoNewPrivileges=yes",
  "ProtectSystem=strict",
  "ProtectHome=yes",
  "PrivateTmp=yes",
  "PrivateDevices=yes",
  "ProtectKernelTunables=yes",
  "ProtectKernelModules=yes",
  "ProtectKernelLogs=yes",
  "ProtectControlGroups=yes",
  "ProtectClock=yes",
  "ProtectHostname=yes",
  "RestrictNamespaces=yes",
  "MemoryDenyWriteExecute=yes",
  "SystemCallFilter=@system-service",
] as const;

/** Where OpenRC's service writes the agent's output (created for the agent user before each start). */
export const OPENRC_LOG = "/var/log/garnetops-agent.log";

/**
 * The OpenRC service (Alpine and other hosts without systemd, ADR 0037 addendum "OpenRC"). OpenRC has no sandbox like systemd's;
 * what it offers is used: supervise-daemon restarts the agent on failure and starts it as the unprivileged user with umask 077 and,
 * on OpenRC 0.45 or newer, no_new_privs. The agent never runs as root, so it holds no capabilities. Memory and CPU limits are cgroup
 * settings that OpenRC applies where it manages cgroup v2 and skips elsewhere; GOMEMLIMIT keeps the Go runtime below them.
 * The environment file is read line by line into an allow-list of names, never sourced as shell.
 */
export const OPENRC_SERVICE = `#!/sbin/openrc-run
# GarnetOps host agent (ADR 0037): reports this host's kernel, packages and SSH settings to GarnetOps. Runs unprivileged.

name="garnetops-agent"
description="GarnetOps host agent"
supervisor="supervise-daemon"
command="/usr/local/bin/garnetops-agent"
command_args="run"
command_user="garnetops-agent:garnetops-agent"
pidfile="/run/\${RC_SVCNAME}.pid"
umask="077"
no_new_privs="yes"
respawn_delay=60
respawn_max=0
output_log="${OPENRC_LOG}"
error_log="${OPENRC_LOG}"
rc_cgroup_settings="memory.max 268435456
cpu.max 20000 100000"

depend() {
	need net
	after firewall
}

start_pre() {
	checkpath -d -o garnetops-agent:garnetops-agent -m 0700 /var/lib/garnetops-agent || return 1
	checkpath -f -o garnetops-agent:garnetops-agent -m 0640 ${OPENRC_LOG} || return 1
	[ -r /etc/garnetops-agent/agent.env ] || { eerror "/etc/garnetops-agent/agent.env is missing"; return 1; }
	# KEY=value lines as systemd's EnvironmentFile= reads them: no shell evaluation, only the agent's own settings.
	while IFS='=' read -r key value; do
		case "$key" in
		GARNETOPS_URL|GARNETOPS_ENROLMENT_CODE|GARNETOPS_HOST_NAME|GARNETOPS_CA_FILE|GARNETOPS_INTERVAL_HOURS) export "$key=$value" ;;
		esac
	done < /etc/garnetops-agent/agent.env
	export GARNETOPS_STATE_DIR=/var/lib/garnetops-agent
	export GOMEMLIMIT=200MiB
}
`;

const shellQuote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;

/**
 * The install script for this installation. It takes the one-time code from the environment (never from the URL, so it does not end
 * up in proxy or server logs), checks the downloaded binary against the SHA-256 written into the script, and installs the service.
 */
export function installScript(publicUrl: string, sums: Partial<Record<AgentArch, string>>): string {
  const base = publicUrl.replace(/\/+$/, "");
  return `#!/bin/sh
# GarnetOps host agent: installs the agent as a systemd service, or as an OpenRC service where OpenRC runs (Alpine) (ADR 0037).
# Read it before you run it. Usage, as root:
#   GARNETOPS_ENROLMENT_CODE=goe_... sh garnetops-agent-install.sh
# Optional: GARNETOPS_HOST_NAME (the name the host reports), GARNETOPS_CA_FILE (a CA bundle for an internal CA).
set -eu

GARNETOPS_URL=${shellQuote(base)}
SHA256_amd64=${shellQuote(sums.amd64 ?? "")}
SHA256_arm64=${shellQuote(sums.arm64 ?? "")}

fail() { echo "garnetops-agent: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "run this as root"
INIT=""
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  INIT=systemd
elif command -v openrc-run >/dev/null 2>&1 || [ -x /sbin/openrc-run ] || [ -x /sbin/openrc ]; then
  [ -d /run/openrc ] || fail "OpenRC is installed but does not run on this system (/run/openrc is missing), so it cannot start the agent. Use the container agent where Docker runs."
  INIT=openrc
else
  fail "neither systemd nor OpenRC runs on this system, so the agent cannot be installed as a service. Use the container agent where Docker runs, or install the agent in a Debian, Ubuntu or Alpine container or VM."
fi

# In a container (e.g. Proxmox VE), check first that systemd can set up the agent's sandbox.
CONTAINER=""
if [ "$INIT" = systemd ]; then
  if command -v systemd-detect-virt >/dev/null 2>&1; then
    CONTAINER=$(systemd-detect-virt --container 2>/dev/null || true)
  elif [ -r /run/systemd/container ]; then
    CONTAINER=$(head -c 40 /run/systemd/container)
  fi
fi
[ "$CONTAINER" = none ] && CONTAINER=""
if [ -n "$CONTAINER" ]; then
  # shellcheck disable=SC2086
  systemd-run --wait --quiet --collect ${SANDBOX_CHECK.map((p) => `-p ${p}`).join(" ")} /bin/true >/dev/null 2>&1 ||
    fail "this is a container ($CONTAINER) in which systemd cannot set up the agent's sandbox (private /tmp and devices, read-only system), so the service would not start. In Proxmox VE, enable Options > Features > Nesting for this container and restart it, or install the agent in a VM. The agent does not run without its sandbox."
fi
[ -n "\${GARNETOPS_ENROLMENT_CODE:-}" ] || fail "set GARNETOPS_ENROLMENT_CODE to the code from Add agent"
case "$GARNETOPS_ENROLMENT_CODE" in goe_*) ;; *) fail "that is not an enrolment code" ;; esac

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64; SUM=$SHA256_amd64 ;;
  aarch64|arm64) ARCH=arm64; SUM=$SHA256_arm64 ;;
  *) fail "unsupported architecture $(uname -m)" ;;
esac
[ -n "$SUM" ] || fail "this installation has no agent for $ARCH"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
URL="$GARNETOPS_URL/api/v1/agent/download/linux-$ARCH"
case "$URL" in https://*) ;; *) fail "the address of this installation must start with https://" ;; esac
CA_OPT=""
if command -v curl >/dev/null 2>&1; then
  [ -n "\${GARNETOPS_CA_FILE:-}" ] && CA_OPT="--cacert $GARNETOPS_CA_FILE"
  # shellcheck disable=SC2086
  curl -fsS --proto =https --tlsv1.2 $CA_OPT -o "$TMP/agent" "$URL" || fail "download failed"
elif command -v wget >/dev/null 2>&1 && wget --help 2>&1 | grep -q -- --https-only; then
  # GNU wget.
  [ -n "\${GARNETOPS_CA_FILE:-}" ] && CA_OPT="--ca-certificate=$GARNETOPS_CA_FILE"
  # shellcheck disable=SC2086
  wget -q --https-only $CA_OPT -O "$TMP/agent" "$URL" || fail "download failed"
elif command -v wget >/dev/null 2>&1; then
  # BusyBox wget (Alpine) has no option to refuse plain HTTP, to name a CA file or to refuse redirects, and checks the
  # certificate only through its openssl helper. The SHA-256 below is what protects the agent either way.
  [ -z "\${GARNETOPS_CA_FILE:-}" ] || fail "GARNETOPS_CA_FILE needs curl or GNU wget (on Alpine: apk add curl)"
  wget -q -O "$TMP/agent" "$URL" || fail "download failed"
else
  fail "curl or wget is needed"
fi
echo "$SUM  $TMP/agent" | sha256sum -c - >/dev/null 2>&1 || fail "the download does not match its checksum"

if ! id garnetops-agent >/dev/null 2>&1; then
  NOLOGIN=/bin/false
  for shell in /usr/sbin/nologin /sbin/nologin; do [ -x "$shell" ] && NOLOGIN=$shell && break; done
  if command -v useradd >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /nonexistent --shell "$NOLOGIN" garnetops-agent
  elif command -v adduser >/dev/null 2>&1 && command -v addgroup >/dev/null 2>&1; then
    # BusyBox (Alpine): a system group and a system user without password and home directory.
    addgroup -S garnetops-agent
    adduser -S -D -H -h /nonexistent -s "$NOLOGIN" -G garnetops-agent garnetops-agent
  else
    fail "useradd or adduser is needed to create the user garnetops-agent"
  fi
fi
install -o root -g root -m 0755 "$TMP/agent" /usr/local/bin/garnetops-agent
install -d -o root -g garnetops-agent -m 0750 /etc/garnetops-agent
umask 077
{
  echo "GARNETOPS_URL=$GARNETOPS_URL"
  echo "GARNETOPS_ENROLMENT_CODE=$GARNETOPS_ENROLMENT_CODE"
  [ -n "\${GARNETOPS_HOST_NAME:-}" ] && echo "GARNETOPS_HOST_NAME=$GARNETOPS_HOST_NAME"
  [ -n "\${GARNETOPS_CA_FILE:-}" ] && echo "GARNETOPS_CA_FILE=$GARNETOPS_CA_FILE"
  true
} > /etc/garnetops-agent/agent.env
chown root:garnetops-agent /etc/garnetops-agent/agent.env
chmod 0640 /etc/garnetops-agent/agent.env
if [ "$INIT" = openrc ]; then
  install -d -o garnetops-agent -g garnetops-agent -m 0700 /var/lib/garnetops-agent
  cat > /etc/init.d/garnetops-agent <<'SERVICE'
${OPENRC_SERVICE}SERVICE
  chmod 0755 /etc/init.d/garnetops-agent
  rc-update add garnetops-agent default >/dev/null
  rc-service garnetops-agent restart
  echo "garnetops-agent: installed and started as an OpenRC service; the host appears in GarnetOps after its first report."
  echo "garnetops-agent: logs in ${OPENRC_LOG}"
  exit 0
fi
cat > /etc/systemd/system/garnetops-agent.service <<'UNIT'
${SYSTEMD_UNIT}UNIT
systemctl daemon-reload
systemctl enable --now garnetops-agent.service
echo "garnetops-agent: installed and started; the host appears in GarnetOps after its first report."
echo "garnetops-agent: logs with: journalctl -u garnetops-agent"
`;
}
