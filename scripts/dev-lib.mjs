/**
 * Helpers shared by scripts/dev.mjs and scripts/dev-stop.mjs. Development only.
 *
 * On Windows, killing a spawned shell does not kill the processes it started,
 * so a stopped `pnpm dev` used to leave API, worker, Vite and PostgreSQL
 * running. These helpers stop whole process trees and recognise the
 * development PostgreSQL so it can be reused or stopped cleanly.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { connect } from "node:net";
import { arch, platform } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const root = join(dirname(fileURLToPath(import.meta.url)), "..");
export const pgDataDir = join(root, ".data", "pg");
export const PG_PORT = 54329;
/** PID of the running `pnpm dev` launcher; it is started with a relative path, so it cannot be found by its command line. */
export const devPidFile = join(root, ".data", "dev.pid");
const isWindows = platform() === "win32";

/** True if something accepts TCP connections on the port (IPv4 or IPv6 loopback). */
export function portInUse(port) {
  const probe = (host) =>
    new Promise((resolve) => {
      const socket = connect({ port, host });
      socket.once("connect", () => {
        socket.destroy();
        resolve(true);
      });
      socket.once("error", () => resolve(false));
      socket.setTimeout(500, () => {
        socket.destroy();
        resolve(false);
      });
    });
  return Promise.all([probe("127.0.0.1"), probe("::1")]).then((r) => r.some(Boolean));
}

export function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM: the process exists but belongs to someone else.
    return error.code === "EPERM";
  }
}

function lockFile() {
  const pidFile = join(pgDataDir, "postmaster.pid");
  if (!existsSync(pidFile)) return null;
  const [pidLine, dataDir, , portLine] = readFileSync(pidFile, "utf8").split(/\r?\n/);
  return { path: pidFile, pid: Number(pidLine), dataDir, port: Number(portLine) };
}

/**
 * PID of the development PostgreSQL if it really runs from .data/pg, else null.
 * A lock file alone is not proof: after a crash it stays behind, and the system
 * may have given its PID to an unrelated program. So the process must be a
 * PostgreSQL server and the port must answer.
 */
export async function runningPostgresPid() {
  const lock = lockFile();
  if (!lock || !Number.isInteger(lock.pid) || lock.port !== PG_PORT) return null;
  if (!lock.dataDir || join(lock.dataDir) !== join(pgDataDir) || !processAlive(lock.pid)) return null;
  if (!commandLineOf(lock.pid)?.toLowerCase().includes("postgres")) return null;
  return (await portInUse(PG_PORT)) ? lock.pid : null;
}

/** Removes a lock file left by a PostgreSQL that is provably gone, so it can start again. */
export async function clearStalePostgresLock() {
  const lock = lockFile();
  if (!lock || (await runningPostgresPid()) || (await portInUse(PG_PORT))) return false;
  rmSync(lock.path, { force: true });
  return true;
}

/** Path of pg_ctl from the embedded-postgres platform package. */
async function pgCtl() {
  // pnpm links packages; resolve from the real location, where the platform package sits next to it.
  const require = createRequire(
    realpathSync(join(root, "node_modules", "embedded-postgres", "package.json")),
  );
  // Package names use "windows" where Node says "win32".
  const os = platform() === "win32" ? "windows" : platform();
  const pkg = require.resolve(`@embedded-postgres/${os}-${arch()}`);
  return (await import(pathToFileURL(pkg).href)).pg_ctl;
}

/** Stops the development PostgreSQL with pg_ctl (fast shutdown), if it runs. */
export async function stopPostgres() {
  if (!(await runningPostgresPid())) return false;
  execFileSync(await pgCtl(), ["stop", "-D", pgDataDir, "-m", "fast", "-w"], { stdio: "ignore" });
  return true;
}

/** Command line of a running process, or null. */
export function commandLineOf(pid) {
  try {
    if (isWindows) {
      return (
        execFileSync(
          "powershell",
          [
            "-NoProfile",
            "-Command",
            `(Get-CimInstance Win32_Process -Filter "ProcessId=${Number(pid)}").CommandLine`,
          ],
          { encoding: "utf8" },
        ).trim() || null
      );
    }
    return (
      execFileSync("ps", ["-o", "args=", "-p", String(Number(pid))], { encoding: "utf8" }).trim() || null
    );
  } catch {
    return null;
  }
}

/** Stops a process and everything it started. */
export function stopTree(pid) {
  try {
    if (isWindows) execFileSync("taskkill", ["/pid", String(pid), "/T", "/F"], { stdio: "ignore" });
    else process.kill(-pid, "SIGTERM"); // the child was started as its own process group
  } catch {
    // Already gone.
  }
}

/**
 * Node processes started from this repository (dev server, API, worker, Vite),
 * excluding the current process. Matched on the repository path and known
 * entry points, so unrelated Node programs are never touched.
 */
export function repoNodeProcesses() {
  const markers = ["src/index.ts", "src\\index.ts", "vite", "scripts/dev.mjs", "scripts\\dev.mjs"];
  let rows = [];
  if (isWindows) {
    const out = execFileSync(
      "powershell",
      [
        "-NoProfile",
        "-Command",
        'Get-CimInstance Win32_Process -Filter "Name=\'node.exe\'" | ForEach-Object { "$($_.ProcessId)`t$($_.CommandLine)" }',
      ],
      { encoding: "utf8" },
    );
    rows = out.split(/\r?\n/).map((l) => l.split("\t"));
  } else {
    const out = execFileSync("ps", ["-eo", "pid=,args="], { encoding: "utf8" });
    rows = out.split("\n").map((l) => {
      const m = /^\s*(\d+)\s+(.*)$/.exec(l);
      return m ? [m[1], m[2]] : [];
    });
  }
  const repo = root.toLowerCase().replaceAll("\\", "/");
  return rows
    .filter(([pid, cmd]) => pid && cmd && Number(pid) !== process.pid)
    .filter(([, cmd]) => {
      const c = cmd.toLowerCase().replaceAll("\\", "/");
      // Both conditions: a known entry point AND this repository's path. Other projects' Node
      // processes (e.g. another app's dev server) never match.
      return c.includes(repo) && markers.some((m) => c.includes(m.toLowerCase().replaceAll("\\", "/")));
    })
    .map(([pid, cmd]) => ({ pid: Number(pid), cmd }));
}
