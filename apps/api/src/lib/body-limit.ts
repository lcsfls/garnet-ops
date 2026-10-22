import { bodyLimit } from "hono/body-limit";
import { createMiddleware } from "hono/factory";

const smallBodies = bodyLimit({ maxSize: 1024 * 1024 });

/** The one route that takes a large body: the GeoIP file upload (ADR 0016). */
export const GEOIP_UPLOAD_PATH = /^\/api\/v1\/attacks\/geoip\/(country|asn)$/;

/**
 * Every request body is limited to 1 MiB, except a PUT of a GeoIP file. That route enforces its own,
 * larger limits while it streams: the compressed size (declared up front and counted), the inflated
 * size, the line length and the row count (packages/core/src/geoip.ts).
 */
export const requestBodyLimit = createMiddleware(async (c, next) => {
  if (c.req.method === "PUT" && GEOIP_UPLOAD_PATH.test(c.req.path)) return next();
  return smallBodies(c, next);
});
