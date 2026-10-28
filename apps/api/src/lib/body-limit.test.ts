import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { requestBodyLimit } from "./body-limit.ts";

const app = new Hono()
  .use("*", requestBodyLimit)
  .all("/api/v1/other", async (c) => c.json({ bytes: (await c.req.arrayBuffer()).byteLength }));

const send = (method: string, path: string, size: number) =>
  app.request(path, {
    method,
    headers: { "content-length": String(size) },
    body: Buffer.alloc(size, 0x61),
  });

describe("request body limit", () => {
  it("keeps 1 MiB for every route and method", async () => {
    expect((await send("POST", "/api/v1/other", 1024 * 1024)).status).toBe(200);
    expect((await send("POST", "/api/v1/other", 1024 * 1024 + 1)).status).toBe(413);
    expect((await send("PUT", "/api/v1/other", 2 * 1024 * 1024)).status).toBe(413);
  });
});
