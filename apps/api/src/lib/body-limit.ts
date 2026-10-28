import { bodyLimit } from "hono/body-limit";

/** Every request body is limited to 1 MiB. No route takes a larger one. */
export const requestBodyLimit = bodyLimit({ maxSize: 1024 * 1024 });
