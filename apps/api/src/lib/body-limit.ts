import { MAX_AGENT_BODY_BYTES } from "@garnetops/core/agent";
import { bodyLimit } from "hono/body-limit";
import { createMiddleware } from "hono/factory";

const ONE_MIB = bodyLimit({ maxSize: 1024 * 1024 });
/** The package lists from a host agent (one image, ADR 0034; the host itself, ADR 0037) are the only larger bodies. */
const AGENT_PACKAGES = bodyLimit({ maxSize: MAX_AGENT_BODY_BYTES });

const LARGE = new Set(["/api/v1/agent/packages", "/api/v1/agent/host-packages"]);

/** Every request body is limited to 1 MiB, except an agent's package lists (8 MiB). */
export const requestBodyLimit = createMiddleware((c, next) =>
  LARGE.has(c.req.path) ? AGENT_PACKAGES(c, next) : ONE_MIB(c, next),
);
