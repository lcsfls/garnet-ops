/**
 * The GarnetOps host agent (ADR 0034).
 *
 *   node apps/agent/src/main.ts proxy   the Docker socket proxy (GET and HEAD on read paths only, no network)
 *   node apps/agent/src/main.ts run     report now and then every GARNETOPS_INTERVAL_HOURS
 *   node apps/agent/src/main.ts once    report once and exit (non-zero on failure)
 */
import { Server, ServerError } from "./client.ts";
import { loadConfig } from "./config.ts";
import { serveProxy } from "./proxy.ts";
import { reportOnce } from "./report.ts";

const command = process.argv[2] ?? "run";
const log = (line: string) => console.log(line);

if (command === "proxy") {
  const socket = process.env.GARNETOPS_DOCKER_SOCKET ?? "/run/garnetops-agent/docker.sock";
  const docker = process.env.GARNETOPS_HOST_DOCKER_SOCKET ?? "/var/run/docker.sock";
  const server = await serveProxy(docker, socket);
  log(`agent proxy: listening on ${socket}, read-only`);
  for (const signal of ["SIGTERM", "SIGINT"] as const)
    process.once(signal, () => server.close(() => process.exit(0)));
} else if (command === "run" || command === "once") {
  const config = loadConfig();
  const server = new Server({ baseUrl: config.GARNETOPS_URL, ...(config.ca ? { ca: config.ca } : {}) });
  const deps = {
    server,
    stateDir: config.GARNETOPS_STATE_DIR,
    dockerSocket: config.GARNETOPS_DOCKER_SOCKET,
    syftBin: config.GARNETOPS_SYFT_BIN,
    ...(config.GARNETOPS_ENROLMENT_CODE ? { enrolmentCode: config.GARNETOPS_ENROLMENT_CODE } : {}),
    ...(config.GARNETOPS_HOST_NAME ? { hostName: config.GARNETOPS_HOST_NAME } : {}),
    log,
  };
  const tick = async (): Promise<boolean> => {
    try {
      const result = await reportOnce(deps);
      log(`agent: reported ${result.containers} containers, ${result.packageLists} package lists`);
      return true;
    } catch (error) {
      if (error instanceof ServerError && error.status === 401) {
        log(
          "agent: GarnetOps refused this host (removed, or the code is not valid); remove the agent or enrol again",
        );
      } else if (error instanceof ServerError && error.code === "module-off") {
        log("agent: hosts and containers are switched off in GarnetOps; trying again later");
      } else {
        log(`agent: report failed: ${(error as Error).message}`);
      }
      return false;
    }
  };
  if (command === "once") {
    process.exit((await tick()) ? 0 : 1);
  }
  await tick();
  const timer = setInterval(tick, config.GARNETOPS_INTERVAL_HOURS * 3600_000);
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    process.once(signal, () => {
      clearInterval(timer);
      process.exit(0);
    });
  }
} else {
  console.error(`unknown command: ${command} (proxy, run or once)`);
  process.exit(2);
}
