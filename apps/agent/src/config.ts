/** The agent's settings, from its environment (the Compose snippet the web app hands out sets them). */
import { readFileSync } from "node:fs";
import { z } from "zod";

const schema = z.object({
  /** The address of the GarnetOps installation. */
  GARNETOPS_URL: z.string().url(),
  /** The one-time code; only read while the host is not enrolled yet. */
  GARNETOPS_ENROLMENT_CODE: z.string().optional(),
  GARNETOPS_STATE_DIR: z.string().default("/var/lib/garnetops-agent"),
  /** The proxy's socket, never the host's Docker socket. */
  GARNETOPS_DOCKER_SOCKET: z.string().default("/run/garnetops-agent/docker.sock"),
  GARNETOPS_INTERVAL_HOURS: z.coerce.number().min(1).max(24).default(6),
  /** A CA bundle for an internal certificate authority. */
  GARNETOPS_CA_FILE: z.string().optional(),
  GARNETOPS_SYFT_BIN: z.string().default("/opt/syft/syft"),
  /** The name the host reports (the container's own host name is the container id). */
  GARNETOPS_HOST_NAME: z.string().max(253).optional(),
});

export type AgentConfig = z.infer<typeof schema> & { ca?: string };

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AgentConfig {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    throw new Error(parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
  }
  const url = new URL(parsed.data.GARNETOPS_URL);
  // Only HTTPS: the end-to-end tests of this repository are the one exception, and only under the test runner.
  const testHttp = env.NODE_ENV === "test" && env.GARNETOPS_ALLOW_HTTP_FOR_TESTS === "1";
  if (url.protocol !== "https:" && !(testHttp && url.protocol === "http:")) {
    throw new Error("GARNETOPS_URL must be an https:// address");
  }
  if (url.username || url.password || url.search || url.hash)
    throw new Error("GARNETOPS_URL must be a plain address");
  return {
    ...parsed.data,
    ...(parsed.data.GARNETOPS_CA_FILE ? { ca: readFileSync(parsed.data.GARNETOPS_CA_FILE, "utf8") } : {}),
  };
}
