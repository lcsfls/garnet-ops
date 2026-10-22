/**
 * The host setup script and the read-only inventory wrapper it installs (ADR 0011).
 *
 * The API renders the script from this fixed template; the only values filled in are the
 * installation's public SSH key, its fingerprint, the allowed source addresses and the wrapper's
 * checksum. The script contains no secret and no timestamp, so the same inputs always give
 * the same bytes and one SHA-256 identifies it (the one-line installer checks it before it
 * runs anything).
 *
 * Everything below is POSIX sh. No line may contain the delimiter of the heredoc that carries the
 * wrapper (see WRAPPER_DELIMITER).
 */
import { createHash } from "node:crypto";
import { DEFAULT_SSH_USER, parseAllowedSource, REPORT_HEADER } from "./hosts.ts";
import { fingerprint } from "./ssh.ts";

/** Changes whenever the text of the script or the wrapper changes. Shown in both headers. */
export const SETUP_TEMPLATE_VERSION = 1;
export const SETUP_FILENAME = "garnetops-host-setup.sh";
/** One-time download links stop working after this long. */
export const SETUP_LINK_MINUTES = 60;

const WRAPPER_DELIMITER = "GARNETOPS_WRAPPER_END";
const WRAPPER_PATH = "/usr/local/lib/garnetops/inventory";

// Formats with ${...} are kept out of the template literals below, where ${ would interpolate.
const DPKG_FORMAT =
  // biome-ignore lint/suspicious/noTemplateCurlyInString: dpkg-query format fields, not a JavaScript template
  "${Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\t${source:Package}\\t${source:Version}\\n";
const RPM_FORMAT = "%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n";

/**
 * The wrapper: what sshd runs for every connection of the access key. It answers the one word
 * `inventory`, prints a report and exits. It reads package databases and the OS release,
 * writes nothing, makes no network call (the update checks run from the local package cache) and
 * needs no root. Every section is optional: a tool that is missing or refuses simply leaves its
 * section out.
 */
export const WRAPPER_SCRIPT = String.raw`#!/bin/sh
# GarnetOps read-only inventory (template version ${SETUP_TEMPLATE_VERSION}).
#
# sshd starts this as the forced command of the GarnetOps access key. It ignores whatever the
# client asked for except the exact word "inventory", prints a report of the installed packages
# and exits. It writes nothing, makes no network call and needs no root.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077

if [ "$SSH_ORIGINAL_COMMAND" != "inventory" ]; then
  echo "garnetops: only the command 'inventory' is allowed" >&2
  exit 2
fi

# Every tool gets thirty seconds at most, where the system has timeout(1).
limited() {
  if command -v timeout >/dev/null 2>&1; then
    timeout 30 "$@"
  else
    "$@"
  fi
}

section() {
  printf '@@section %s\n' "$1"
}

if command -v logger >/dev/null 2>&1; then
  logger -t garnetops -p auth.info "inventory requested" 2>/dev/null
fi

printf '%s\n' '${REPORT_HEADER}'

section os-release
if [ -r /etc/os-release ]; then
  head -n 50 /etc/os-release
elif [ -r /usr/lib/os-release ]; then
  head -n 50 /usr/lib/os-release
fi

section kernel
uname -r

section machine
uname -m

if command -v dpkg-query >/dev/null 2>&1; then
  section dpkg
  limited dpkg-query -W -f='${DPKG_FORMAT}' 2>/dev/null
fi

if command -v rpm >/dev/null 2>&1; then
  section rpm
  limited rpm -qa --qf '${RPM_FORMAT}' 2>/dev/null
fi

if command -v apk >/dev/null 2>&1; then
  section apk
  limited apk list -I 2>/dev/null
  section apk-v
  limited apk info -v 2>/dev/null
fi

# Pending updates, from the local package cache only (no refresh, no network).
if command -v apt >/dev/null 2>&1 && command -v dpkg-query >/dev/null 2>&1; then
  section updates-apt
  limited apt list --upgradable 2>/dev/null
fi

if command -v dnf >/dev/null 2>&1; then
  section updates-dnf
  limited dnf -C -q check-update 2>/dev/null
elif command -v yum >/dev/null 2>&1; then
  section updates-dnf
  limited yum -C -q check-update 2>/dev/null
fi

if command -v apk >/dev/null 2>&1; then
  section updates-apk
  limited apk version -l '<' 2>/dev/null
fi

printf '@@end\n'
exit 0
`;

export const WRAPPER_SHA256 = createHash("sha256").update(WRAPPER_SCRIPT).digest("hex");

export interface SetupScriptInput {
  /** The installation's public key in authorized_keys format (`ssh-ed25519 AAAA… comment`). */
  publicKey: string;
  /** Addresses the key may be used from, as accepted by parseAllowedSource. */
  allowedSource: string;
}

export interface SetupScript {
  script: string;
  /** SHA-256 of the script, hex. */
  sha256: string;
  filename: string;
  keyFingerprint: string;
  wrapperSha256: string;
}

const PUBLIC_KEY = /^(ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA[A-Za-z0-9+/]{44}) ?([A-Za-z0-9@._:-]{0,100})$/;

/** Renders the setup script. Refuses values that are not exactly the shapes the template expects. */
export function renderSetupScript(input: SetupScriptInput): SetupScript {
  const key = PUBLIC_KEY.exec(input.publicKey.trim());
  if (!key) throw new Error("The public key is not an Ed25519 key");
  const source = parseAllowedSource(input.allowedSource);
  if (!source.ok) throw new Error(`The allowed source is not valid: ${source.problem}`);
  if (!/^[0-9A-Fa-f:./,]+$/.test(source.value))
    throw new Error("The allowed source has unexpected characters");
  const publicKey = `${key[1]} ${key[2] || "garnetops-host-access"}`;
  const keyFingerprint = fingerprint((key[1] as string).split(" ")[1] as string);
  if (WRAPPER_SCRIPT.includes(`\n${WRAPPER_DELIMITER}\n`))
    throw new Error("The wrapper contains its own delimiter");

  const script = String.raw`#!/bin/sh
# GarnetOps host setup (template version ${SETUP_TEMPLATE_VERSION})
#
# Prepares this server for agentless, read-only inventory by GarnetOps. There is no agent and
# nothing keeps running: GarnetOps connects over SSH, runs one fixed command and reads the
# list of installed packages. Read this script before you run it. It contains no secret.
#
# What it does:
#   1. Creates the system account "${DEFAULT_SSH_USER}": no password, no home directory of its own
#      that it could write to, and no way to log in except with the key below.
#   2. Installs ${WRAPPER_PATH} (owned by root). It answers the single word "inventory" and
#      ignores every other command. It reads the OS release, the kernel version, dpkg, rpm and apk
#      databases and the local update cache. It writes nothing and makes no network call.
#   3. Writes the account's authorized_keys (owned by root, so the account cannot change it) with
#      one line: the GarnetOps access key, valid only from the source addresses below, only for
#      the wrapper (options "restrict", "from" and "command").
#   4. Prints the SSH host key fingerprints of this machine, to compare with the fingerprint that
#      GarnetOps asks you to confirm.
#
# Undo everything:  sh ${SETUP_FILENAME} --uninstall
# Safe to run again: every step checks what is already there.
#
# Access key fingerprint : ${keyFingerprint}
# Allowed source         : ${source.value}
# Wrapper SHA-256        : ${WRAPPER_SHA256}
set -eu
PATH="$PATH:/usr/sbin:/sbin"
export PATH

SSH_USER="${DEFAULT_SSH_USER}"
ALLOWED_SOURCE="${source.value}"
PUBLIC_KEY="${publicKey}"
KEY_FINGERPRINT="${keyFingerprint}"
WRAPPER_SHA256="${WRAPPER_SHA256}"
HOME_DIR="/var/lib/garnetops"
LIB_DIR="/usr/local/lib/garnetops"
WRAPPER="${WRAPPER_PATH}"
SSH_DIR="$HOME_DIR/.ssh"
AUTH_KEYS="$SSH_DIR/authorized_keys"

say() {
  printf '%s\n' "$*"
}

die() {
  printf 'garnetops-setup: %s\n' "$*" >&2
  exit 1
}

usage() {
  say "Usage: sh $0 [--uninstall]"
  say "  (no option)  prepare this server for GarnetOps inventory"
  say "  --uninstall  remove the account, the wrapper and the key again"
}

need_root() {
  [ "$(id -u)" -eq 0 ] || die "this script must run as root (try: sudo sh $0)"
}

user_home() {
  awk -F: -v u="$SSH_USER" '$1 == u { print $6 }' /etc/passwd
}

install_all() {
  need_root
  existing_home="$(user_home)"
  if [ -n "$existing_home" ]; then
    [ "$existing_home" = "$HOME_DIR" ] || die "the account $SSH_USER already exists with another home directory ($existing_home); not touching it"
    say "account $SSH_USER: already present"
  else
    if command -v useradd >/dev/null 2>&1; then
      useradd --system --home-dir "$HOME_DIR" --no-create-home --shell /bin/sh --comment "GarnetOps read-only inventory" "$SSH_USER"
    elif command -v adduser >/dev/null 2>&1; then
      adduser -S -D -H -h "$HOME_DIR" -s /bin/sh -g "GarnetOps read-only inventory" "$SSH_USER"
    else
      die "neither useradd nor adduser found; create the account $SSH_USER by hand and run this script again"
    fi
    say "account $SSH_USER: created"
  fi

  # No password can match "*", but sshd still accepts keys (some systems refuse the "!" of a locked account).
  if grep -q "^$SSH_USER:!" /etc/shadow 2>/dev/null; then
    if command -v usermod >/dev/null 2>&1; then
      usermod -p '*' "$SSH_USER" 2>/dev/null || true
    elif command -v chpasswd >/dev/null 2>&1; then
      printf '%s:*\n' "$SSH_USER" | chpasswd -e 2>/dev/null || true
    fi
  fi

  mkdir -p "$HOME_DIR" "$SSH_DIR" "$LIB_DIR"
  chown root:root "$HOME_DIR" "$SSH_DIR" "$LIB_DIR"
  chmod 755 "$HOME_DIR" "$SSH_DIR" "$LIB_DIR"

  tmp="$(mktemp "$LIB_DIR/.inventory.XXXXXX")"
  cat > "$tmp" <<'${WRAPPER_DELIMITER}'
${WRAPPER_SCRIPT}${WRAPPER_DELIMITER}
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$tmp" | awk '{ print $1 }')"
    if [ "$actual" != "$WRAPPER_SHA256" ]; then
      rm -f "$tmp"
      die "the wrapper was damaged on its way here (checksum $actual); nothing was changed"
    fi
  fi
  chown root:root "$tmp"
  chmod 755 "$tmp"
  mv -f "$tmp" "$WRAPPER"
  say "wrapper: installed $WRAPPER"

  tmp="$(mktemp "$SSH_DIR/.authorized_keys.XXXXXX")"
  printf 'restrict,from="%s",command="%s" %s\n' "$ALLOWED_SOURCE" "$WRAPPER" "$PUBLIC_KEY" > "$tmp"
  chown root:root "$tmp"
  chmod 644 "$tmp"
  mv -f "$tmp" "$AUTH_KEYS"
  say "authorized_keys: written $AUTH_KEYS (key only from $ALLOWED_SOURCE)"

  if command -v restorecon >/dev/null 2>&1; then
    restorecon -R "$HOME_DIR" "$LIB_DIR" 2>/dev/null || true
  fi

  if command -v ssh-keygen >/dev/null 2>&1; then
    shown="$(ssh-keygen -lf "$AUTH_KEYS" 2>/dev/null | awk '{ print $2 }')"
    if [ "$shown" = "$KEY_FINGERPRINT" ]; then
      say "authorized_keys: key $KEY_FINGERPRINT parsed correctly"
    else
      say "warning: could not confirm the key in $AUTH_KEYS with ssh-keygen"
    fi
  fi

  if command -v sshd >/dev/null 2>&1; then
    config="$(sshd -T 2>/dev/null || true)"
    if printf '%s\n' "$config" | grep -Eqi '^(allowusers|allowgroups) '; then
      say "note: sshd limits logins with AllowUsers or AllowGroups; add $SSH_USER there"
    fi
    if printf '%s\n' "$config" | grep -Eqi '^pubkeyauthentication no'; then
      say "note: sshd has public key authentication switched off"
    fi
  fi

  say ""
  say "Done. Next, GarnetOps shows the SSH host key it found on this machine. Compare it with:"
  found=0
  for pub in /etc/ssh/ssh_host_*_key.pub; do
    if [ -f "$pub" ] && command -v ssh-keygen >/dev/null 2>&1; then
      ssh-keygen -lf "$pub" || true
      found=1
    fi
  done
  [ "$found" -eq 1 ] || say "(no host key files found in /etc/ssh; run: ssh-keygen -lf <your host key .pub file>)"
}

uninstall_all() {
  need_root
  existing_home="$(user_home)"
  if [ -n "$existing_home" ] && [ "$existing_home" != "$HOME_DIR" ]; then
    die "the account $SSH_USER has another home directory ($existing_home); not removing it"
  fi
  if [ -e "$AUTH_KEYS" ]; then
    say "authorized_keys: removed"
  else
    say "authorized_keys: not present"
  fi
  rm -f "$AUTH_KEYS" "$SSH_DIR"/.authorized_keys.*
  rmdir "$SSH_DIR" 2>/dev/null || true
  if [ -e "$WRAPPER" ]; then
    say "wrapper: removed"
  else
    say "wrapper: not present"
  fi
  rm -f "$WRAPPER" "$LIB_DIR"/.inventory.*
  rmdir "$LIB_DIR" 2>/dev/null || true
  if [ -n "$existing_home" ]; then
    if userdel "$SSH_USER" 2>/dev/null || deluser "$SSH_USER" >/dev/null 2>&1; then
      say "account $SSH_USER: removed"
    else
      say "warning: could not remove the account $SSH_USER (still logged in?); remove it by hand"
    fi
  else
    say "account $SSH_USER: not present"
  fi
  rmdir "$HOME_DIR" 2>/dev/null || true
}

case "$#" in
  0)
    install_all
    ;;
  1)
    case "$1" in
      --uninstall) uninstall_all ;;
      --help | -h) usage ;;
      *)
        usage >&2
        exit 2
        ;;
    esac
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
`;

  return {
    script,
    sha256: createHash("sha256").update(script).digest("hex"),
    filename: SETUP_FILENAME,
    keyFingerprint,
    wrapperSha256: WRAPPER_SHA256,
  };
}

/** Quotes a value for a POSIX shell. */
function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

/**
 * The one-line installer: download, check the SHA-256 and only then run. If the checksum does
 * not match, `sha256sum -c` fails and nothing is executed.
 */
export function setupOneLiner(url: string, sha256: string): string {
  if (!/^[0-9a-f]{64}$/.test(sha256)) throw new Error("Not a SHA-256");
  return `curl -fsSLo ${SETUP_FILENAME} ${shellQuote(url)} && echo "${sha256}  ${SETUP_FILENAME}" | sha256sum -c - && sudo sh ${SETUP_FILENAME}`;
}
