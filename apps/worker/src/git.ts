import { existsSync } from "node:fs";
import { platform } from "node:os";
import { delimiter, isAbsolute, join } from "node:path";
import { scanErrorMessage } from "@garnetops/core";
import { CommandError, run } from "./run.ts";

export interface SshOptions {
  /** Absolute path of the ssh client; the same binary was probed for its key exchanges. */
  bin: string;
  /** Private key file inside the scan directory (mode 0600), removed right after the clone. */
  privateKeyFile: string;
  /** known_hosts file: the pinned keys, or empty on first contact. */
  knownHostsFile: string;
  /** True if knownHostsFile holds pinned keys; false accepts and records the key on first contact. */
  pinned: boolean;
  /** Key exchanges to offer, best first (see sshKexAlgorithms). */
  kex: string[];
}

export interface CloneOptions {
  url: string;
  dir: string;
  /** Empty scratch directory used as HOME, so git finds no user files. */
  home: string;
  branch: string | null;
  token: string | null;
  ssh?: SshOptions | null;
}

/**
 * Key exchanges we offer, best first: hybrid post-quantum first (protects a recorded session
 * against later decryption), then classical ones that BSI TR-02102-4 still accepts. SHA-1 and
 * small Diffie-Hellman groups are never offered.
 */
export const PREFERRED_KEX = [
  "mlkem768x25519-sha256",
  "sntrup761x25519-sha512",
  "sntrup761x25519-sha512@openssh.com",
  "curve25519-sha256",
  "curve25519-sha256@libssh.org",
  "ecdh-sha2-nistp521",
  "ecdh-sha2-nistp384",
  "ecdh-sha2-nistp256",
  "diffie-hellman-group18-sha512",
  "diffie-hellman-group16-sha512",
  "diffie-hellman-group14-sha256",
];

/** The preferred key exchanges the ssh client supports, in our order. Unknown names would make ssh refuse to start. */
export function sshKexAlgorithms(supported: string[]): string[] {
  const known = new Set(supported.map((s) => s.trim()));
  return PREFERRED_KEX.filter((k) => known.has(k));
}

/** Quotes a value for the POSIX shell git runs GIT_SSH_COMMAND with. */
function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

/**
 * The ssh command git runs. No user or system ssh configuration, no agent, no forwarding,
 * no prompts, public key authentication with our key only, and host keys checked against
 * the pinned file (or recorded on first contact, never silently replaced).
 */
export function sshCommand(ssh: SshOptions): string {
  const slash = (p: string) => p.replaceAll("\\", "/");
  const options = [
    "BatchMode=yes",
    "IdentitiesOnly=yes",
    "IdentityAgent=none",
    "PreferredAuthentications=publickey",
    "PasswordAuthentication=no",
    "KbdInteractiveAuthentication=no",
    `StrictHostKeyChecking=${ssh.pinned ? "yes" : "accept-new"}`,
    `UserKnownHostsFile=${slash(ssh.knownHostsFile)}`,
    "GlobalKnownHostsFile=none",
    "UpdateHostKeys=no",
    "HashKnownHosts=no",
    "CheckHostIP=no",
    "ForwardAgent=no",
    "ForwardX11=no",
    "ClearAllForwardings=yes",
    "PermitLocalCommand=no",
    "ControlMaster=no",
    "ControlPath=none",
    "ProxyJump=none",
    "ConnectTimeout=20",
    "ServerAliveInterval=15",
    "ServerAliveCountMax=4",
    `KexAlgorithms=${ssh.kex.join(",")}`,
  ];
  return [
    shellQuote(slash(ssh.bin)),
    "-F",
    "none",
    "-i",
    shellQuote(slash(ssh.privateKeyFile)),
    ...options.flatMap((o) => ["-o", shellQuote(o)]),
  ].join(" ");
}

/** Finds the ssh client on PATH (absolute path), or null. */
export function findSsh(path = process.env.PATH ?? ""): string | null {
  const names = platform() === "win32" ? ["ssh.exe"] : ["ssh"];
  for (const dir of path.split(delimiter)) {
    if (!dir || !isAbsolute(dir)) continue;
    for (const name of names) {
      const candidate = join(dir, name);
      if (existsSync(candidate)) return candidate;
    }
  }
  return null;
}

let kexCache: { bin: string; kex: string[] } | null = null;

/** ssh client and the key exchanges to offer, probed once per worker process. */
export async function sshClient(): Promise<{ bin: string; kex: string[] }> {
  if (kexCache) return kexCache;
  const bin = process.env.GARNETOPS_SSH_BIN || findSsh();
  if (!bin) throw new Error(scanErrorMessage("sshClientMissing"));
  const { stdout } = await run(bin, ["-Q", "kex"], { env: { PATH: process.env.PATH }, timeoutMs: 10_000 });
  const kex = sshKexAlgorithms(stdout.split(/\r?\n/));
  if (kex.length === 0) throw new Error(scanErrorMessage("sshNoKeyExchange"));
  kexCache = { bin, kex };
  return kexCache;
}

/**
 * Environment and arguments for a shallow, hardened clone of a repository we
 * do not trust. Kept free of side effects so the hardening is unit-tested.
 *
 * - The user's and system git configuration are ignored.
 * - Only https and ssh transports are allowed (no file://, ext::, git://).
 * - No prompts, no credential storage, no LFS downloads, no submodules, no hooks run.
 * - The token is passed through the environment to an inline credential helper,
 *   never on the command line (which other local users could read) and never in the URL.
 * - The helper is scoped to the repository's own origin and HTTP redirects are refused,
 *   so a server cannot redirect git to another host and receive the token there.
 */
export function cloneCommand(options: CloneOptions): { args: string[]; env: NodeJS.ProcessEnv } {
  const nullDevice = platform() === "win32" ? "NUL" : "/dev/null";
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    SystemRoot: process.env.SystemRoot,
    HOME: options.home,
    USERPROFILE: options.home,
    GIT_TERMINAL_PROMPT: "0",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: nullDevice,
    GIT_LFS_SKIP_SMUDGE: "1",
    GIT_ASKPASS: "",
    SSH_ASKPASS: "",
    SSH_AUTH_SOCK: "",
    ...(options.ssh ? { GIT_SSH_COMMAND: sshCommand(options.ssh), GIT_SSH_VARIANT: "ssh" } : {}),
    ...(options.token ? { GARNETOPS_GIT_TOKEN: options.token } : {}),
  };

  const config = [
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.https.allow=always",
    "-c",
    "protocol.ssh.allow=always",
    "-c",
    `core.hooksPath=${nullDevice}`,
    "-c",
    "core.symlinks=false",
    "-c",
    "credential.helper=",
    "-c",
    "http.followRedirects=false",
    ...(options.token
      ? [
          "-c",
          `credential.${new URL(options.url).origin}.helper=!f() { echo username=x-access-token; echo "password=$GARNETOPS_GIT_TOKEN"; }; f`,
        ]
      : []),
  ];

  const args = [
    ...config,
    "clone",
    "--depth=1",
    "--single-branch",
    "--no-tags",
    "--no-recurse-submodules",
    ...(options.branch ? ["--branch", options.branch] : []),
    "--",
    options.url,
    options.dir,
  ];
  return { args, env };
}

export async function shallowClone(options: CloneOptions): Promise<{ commitSha: string; branch: string }> {
  if (options.ssh && options.token) throw new Error("A clone uses a token or an SSH key, not both");
  const { args, env } = cloneCommand(options);
  try {
    await run("git", args, { env, timeoutMs: 5 * 60_000, redact: options.token ? [options.token] : [] });
  } catch (error) {
    if (error instanceof CommandError) throw new Error(cloneErrorMessage(error.stderr));
    throw error;
  }

  const head = await run("git", ["-C", options.dir, "rev-parse", "HEAD"], { env, timeoutMs: 30_000 });
  const ref = await run("git", ["-C", options.dir, "rev-parse", "--abbrev-ref", "HEAD"], {
    env,
    timeoutMs: 30_000,
  });
  return { commitSha: head.stdout.trim(), branch: ref.stdout.trim() };
}

/** Maps git's stderr to a short, user-safe message (no raw output, no URLs with secrets). */
export function cloneErrorMessage(stderr: string): string {
  const s = stderr.toLowerCase();
  if (s.includes("remote host identification has changed") || s.includes("host key verification failed")) {
    return scanErrorMessage("hostKeyMismatch");
  }
  if (s.includes("permission denied (publickey")) return scanErrorMessage("deployKeyRefused");
  if (s.includes("no matching key exchange")) return scanErrorMessage("serverNoKeyExchange");
  if (s.includes("remote branch") && s.includes("not found")) return scanErrorMessage("branchNotFound");
  if (s.includes("authentication failed") || s.includes("could not read username") || s.includes("403")) {
    return scanErrorMessage("accessRefused");
  }
  if (s.includes("not found") || s.includes("404") || s.includes("does not exist")) {
    return scanErrorMessage("repositoryNotFound");
  }
  if (s.includes("could not resolve host") || s.includes("timed out") || s.includes("connection")) {
    return scanErrorMessage("hostUnreachable");
  }
  return scanErrorMessage("cloneFailed");
}
