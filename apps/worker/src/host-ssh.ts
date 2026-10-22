/**
 * The ssh side of servers (ADR 0011): host key scan, the hardened ssh command, a runner that
 * bounds time and output, and the mapping of ssh's complaints to short safe messages.
 *
 * Nothing here uses a shell: programs get an argument array, the address was validated before
 * it was stored and is checked again, and the output of a server is data, never a command.
 */
import { spawn } from "node:child_process";
import { lookup } from "node:dns/promises";
import { HostError, type HostErrorCode } from "@garnetops/core";
import { checkHostAddress, HOST_KEY_ALIAS, parseKeyscan, type ScannedHostKey } from "@garnetops/core/hosts";
import { isForbiddenAddress } from "@garnetops/core/notifications";
import { findOnPath, sshClient } from "./git.ts";

export interface Captured {
  /** Exit code of the program; null if it was stopped. */
  code: number | null;
  stdout: Buffer;
  /** At most 16 KiB; only ever mapped to a short message, never stored or shown. */
  stderr: string;
  timedOut: boolean;
  tooLarge: boolean;
}

/**
 * Runs a program without a shell, with a time limit and a cap on its output. When a limit is
 * hit the program is killed and the result says which. The standard input is closed.
 */
export function runCapped(
  command: string,
  args: string[],
  options: { env: NodeJS.ProcessEnv; timeoutMs: number; maxBytes: number },
): Promise<Captured> {
  return new Promise((resolve, reject) => {
    const posix = process.platform !== "win32";
    const child = spawn(command, args, {
      env: options.env,
      shell: false,
      windowsHide: true,
      // Its own process group on Unix, so a limit stops everything the program started.
      detached: posix,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const chunks: Buffer[] = [];
    let size = 0;
    let stderr = "";
    let timedOut = false;
    let tooLarge = false;
    let done = false;
    const stop = () => {
      try {
        if (posix && child.pid) process.kill(-child.pid, "SIGKILL");
        else child.kill("SIGKILL");
      } catch {
        // Already gone.
      }
    };
    const finish = (code: number | null) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      child.stdout.destroy();
      child.stderr.destroy();
      resolve({ code, stdout: Buffer.concat(chunks), stderr, timedOut, tooLarge });
    };
    child.stdout.on("data", (d: Buffer) => {
      size += d.length;
      if (size > options.maxBytes) {
        if (!tooLarge) {
          tooLarge = true;
          stop();
        }
        return;
      }
      chunks.push(d);
    });
    child.stderr.on("data", (d: Buffer) => {
      if (stderr.length < 16 * 1024) stderr += d.toString("utf8");
    });
    const timer = setTimeout(() => {
      timedOut = true;
      stop();
    }, options.timeoutMs);
    child.on("error", (error) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      reject(new Error(`Could not start ${command}: ${error.message}`));
    });
    // A program that was stopped may have left children holding the pipes open: do not wait for them.
    child.on("exit", (code) => {
      if (timedOut || tooLarge) finish(code);
    });
    child.on("close", (code) => finish(code));
  });
}

/** Environment for ssh and ssh-keyscan: nothing from the worker's own, no agent, no askpass. */
export function sshEnv(home: string): NodeJS.ProcessEnv {
  return { PATH: process.env.PATH, HOME: home, SSH_AUTH_SOCK: "", SSH_ASKPASS: "", LC_ALL: "C" };
}

export interface HostSshOptions {
  /** The address ssh connects to: an IP address the worker resolved and checked itself. */
  target: string;
  port: number;
  user: string;
  keyFile: string;
  knownHostsFile: string;
  kex: string[];
}

/**
 * Arguments of the inventory call. No ssh configuration file, no agent, no forwarding, no
 * pseudo-terminal, key authentication with our key only, and the host key must match the
 * pinned one exactly (the known_hosts file holds that one key under a fixed alias, so the
 * connection address does not matter). The remote command is the single word `inventory`.
 */
export function hostSshArgs(o: HostSshOptions): string[] {
  const options = [
    "BatchMode=yes",
    "IdentitiesOnly=yes",
    "IdentityAgent=none",
    "PreferredAuthentications=publickey",
    "PasswordAuthentication=no",
    "KbdInteractiveAuthentication=no",
    "StrictHostKeyChecking=yes",
    `HostKeyAlias=${HOST_KEY_ALIAS}`,
    `UserKnownHostsFile=${o.knownHostsFile}`,
    "GlobalKnownHostsFile=none",
    "UpdateHostKeys=no",
    "HashKnownHosts=no",
    "CheckHostIP=no",
    "VerifyHostKeyDNS=no",
    "ForwardAgent=no",
    "ForwardX11=no",
    "ClearAllForwardings=yes",
    "PermitLocalCommand=no",
    "ControlMaster=no",
    "ControlPath=none",
    "ProxyJump=none",
    "ProxyCommand=none",
    "RequestTTY=no",
    "LogLevel=ERROR",
    "ConnectTimeout=20",
    "ServerAliveInterval=15",
    "ServerAliveCountMax=3",
    `KexAlgorithms=${o.kex.join(",")}`,
  ];
  return [
    "-F",
    "none",
    "-T",
    "-i",
    o.keyFile,
    "-l",
    o.user,
    "-p",
    String(o.port),
    ...options.flatMap((option) => ["-o", option]),
    "--",
    o.target,
    "inventory",
  ];
}

/** Maps ssh's error output to a short safe message. The output itself is dropped. */
export function classifySshFailure(result: Pick<Captured, "code" | "stderr">): HostErrorCode {
  const s = result.stderr.toLowerCase();
  if (
    s.includes("remote host identification has changed") ||
    s.includes("host key verification failed") ||
    s.includes("offending")
  ) {
    return "hostKeyChanged";
  }
  if (s.includes("permission denied")) return "accessRefused";
  if (s.includes("no matching key exchange")) return "noKeyExchange";
  if (s.includes("could not resolve hostname")) return "addressUnresolvable";
  if (
    s.includes("timed out") ||
    s.includes("refused") ||
    s.includes("no route to host") ||
    s.includes("unreachable") ||
    s.includes("connection closed") ||
    s.includes("connection reset") ||
    s.includes("kex_exchange_identification") ||
    s.includes("broken pipe")
  ) {
    return "hostUnreachable";
  }
  // ssh passes the remote command's exit status on; 255 is ssh's own failure.
  if (result.code !== null && result.code !== 255) return "commandRefused";
  return "hostUnreachable";
}

/**
 * Turns a stored address into the IP address to connect to. A host name is resolved here and
 * every answer is checked, so the address that was checked is the address ssh connects to
 * (no second lookup an attacker's DNS could answer differently), and a name that points at
 * loopback, link-local or metadata addresses is refused.
 */
export async function resolveTarget(address: string): Promise<string> {
  const check = checkHostAddress(address);
  if (!check.ok) throw new HostError("addressRefused");
  if (check.kind !== "hostname") return check.address;
  let answers: { address: string }[];
  try {
    answers = await lookup(check.address, { all: true, verbatim: true });
  } catch {
    throw new HostError("addressUnresolvable");
  }
  const first = answers[0];
  if (!first) throw new HostError("addressUnresolvable");
  if (answers.some((a) => isForbiddenAddress(a.address))) throw new HostError("addressRefused");
  return first.address;
}

export interface Ssh {
  bin: string;
  kex: string[];
  keyscanBin: string;
}

/** The ssh client, its key exchanges and ssh-keyscan (same directory, or on PATH). */
export async function sshTools(): Promise<Ssh> {
  const client = await sshClient().catch(() => {
    throw new HostError("sshClientMissing");
  });
  const keyscanBin = process.env.GARNETOPS_SSH_KEYSCAN_BIN || findOnPath("ssh-keyscan");
  if (!keyscanBin) throw new HostError("sshClientMissing");
  return { ...client, keyscanBin };
}

/**
 * Reads the SSH host keys a server presents, with `ssh-keyscan` (it only looks; nothing is
 * trusted yet). The result is a proposal for an admin to confirm, never pinned by itself.
 */
export async function scanHostKeys(
  tools: Ssh,
  target: string,
  port: number,
  home: string,
): Promise<{ keys: ScannedHostKey[] }> {
  const result = await runCapped(
    tools.keyscanBin,
    ["-T", "10", "-p", String(port), "-t", "ed25519,ecdsa,rsa", "--", target],
    { env: sshEnv(home), timeoutMs: 30_000, maxBytes: 64 * 1024 },
  ).catch(() => {
    throw new HostError("sshClientMissing");
  });
  const { keys, weak } = parseKeyscan(result.stdout.toString("utf8"));
  if (keys.length === 0) throw new HostError(weak ? "keyscanWeakKey" : "keyscanFailed");
  return { keys };
}
