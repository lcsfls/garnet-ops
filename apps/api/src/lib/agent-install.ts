/**
 * The systemd host agent's installation (ADR 0037): this installation serves the agent binaries it was built with and a script that
 * installs one of them as a hardened systemd service. Nothing comes from the internet, so it works air-gapped, and the version
 * always matches the server.
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

const shellQuote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;

/**
 * The install script for this installation. It takes the one-time code from the environment (never from the URL, so it does not end
 * up in proxy or server logs), checks the downloaded binary against the SHA-256 written into the script, and installs the service.
 */
export function installScript(publicUrl: string, sums: Partial<Record<AgentArch, string>>): string {
  const base = publicUrl.replace(/\/+$/, "");
  return `#!/bin/sh
# GarnetOps host agent: installs the agent as a systemd service (ADR 0037).
# Read it before you run it. Usage, as root:
#   GARNETOPS_ENROLMENT_CODE=goe_... sh garnetops-agent-install.sh
# Optional: GARNETOPS_HOST_NAME (the name the host reports), GARNETOPS_CA_FILE (a CA bundle for an internal CA).
set -eu

GARNETOPS_URL=${shellQuote(base)}
SHA256_amd64=${shellQuote(sums.amd64 ?? "")}
SHA256_arm64=${shellQuote(sums.arm64 ?? "")}

fail() { echo "garnetops-agent: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "run this as root"
command -v systemctl >/dev/null 2>&1 || fail "systemd is needed"
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
CA_OPT=""
if command -v curl >/dev/null 2>&1; then
  [ -n "\${GARNETOPS_CA_FILE:-}" ] && CA_OPT="--cacert $GARNETOPS_CA_FILE"
  # shellcheck disable=SC2086
  curl -fsS --proto =https --tlsv1.2 $CA_OPT -o "$TMP/agent" "$URL" || fail "download failed"
elif command -v wget >/dev/null 2>&1; then
  [ -n "\${GARNETOPS_CA_FILE:-}" ] && CA_OPT="--ca-certificate=$GARNETOPS_CA_FILE"
  # shellcheck disable=SC2086
  wget -q --https-only $CA_OPT -O "$TMP/agent" "$URL" || fail "download failed"
else
  fail "curl or wget is needed"
fi
echo "$SUM  $TMP/agent" | sha256sum -c - >/dev/null 2>&1 || fail "the download does not match its checksum"

id garnetops-agent >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin garnetops-agent
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
cat > /etc/systemd/system/garnetops-agent.service <<'UNIT'
${SYSTEMD_UNIT}UNIT
systemctl daemon-reload
systemctl enable --now garnetops-agent.service
echo "garnetops-agent: installed and started; the host appears in GarnetOps after its first report."
echo "garnetops-agent: logs with: journalctl -u garnetops-agent"
`;
}
