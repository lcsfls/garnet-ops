#!/usr/bin/env node
/**
 * Stops everything `pnpm dev` started from this repository, including leftovers
 * of earlier runs: API, worker, Vite (with their child processes) and the
 * development PostgreSQL. Only processes started from this repository's path
 * are touched. Development only.
 */
import { existsSync, readFileSync, rmSync } from "node:fs";
import {
  clearStalePostgresLock,
  commandLineOf,
  devPidFile,
  processAlive,
  repoNodeProcesses,
  runningPostgresPid,
  stopPostgres,
  stopTree,
} from "./dev-lib.mjs";

// PostgreSQL first and gracefully (pg_ctl): stopping the launcher's process tree would
// otherwise kill it hard, and it would have to recover on the next start.
const pgPid = await runningPostgresPid();
if (pgPid) {
  await stopPostgres();
  console.log(`dev:stop: stopped PostgreSQL (${pgPid})`);
} else {
  console.log("dev:stop: PostgreSQL is not running");
  if (await clearStalePostgresLock()) console.log("dev:stop: removed a stale PostgreSQL lock file");
}

// Then the launcher, so it cannot restart anything while its children stop.
if (existsSync(devPidFile)) {
  const pid = Number(readFileSync(devPidFile, "utf8"));
  // A stale file may name a PID the system has since given to another program.
  if (Number.isInteger(pid) && processAlive(pid) && commandLineOf(pid)?.includes("dev.mjs")) {
    stopTree(pid);
    console.log(`dev:stop: stopped the dev launcher (${pid})`);
  }
  rmSync(devPidFile, { force: true });
}

const processes = repoNodeProcesses();
for (const { pid, cmd } of processes) {
  stopTree(pid);
  console.log(`dev:stop: stopped ${pid} ${cmd.slice(-60).trim()}`);
}
if (processes.length === 0) console.log("dev:stop: no API, worker or Vite processes found");
