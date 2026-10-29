import { MAX_AGENT_BODY_BYTES } from "@garnetops/core/agent";
import { bodyLimit } from "hono/body-limit";
import { createMiddleware } from "hono/factory";

const ONE_MIB = bodyLimit({ maxSize: 1024 * 1024 });
/** The package list of one image from a host agent (ADR 0034) is the only larger body. */
const AGENT_PACKAGES = bodyLimit({ maxSize: MAX_AGENT_BODY_BYTES });

/** Every request body is limited to 1 MiB, except an agent's package list (8 MiB). */
export const requestBodyLimit = createMiddleware((c, next) =>
  c.req.path === "/api/v1/agent/packages" ? AGENT_PACKAGES(c, next) : ONE_MIB(c, next),
);
