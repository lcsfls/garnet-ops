import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";

vi.mock("../env.ts", () => ({ env: { GARNETOPS_MAX_RESTORE_MB: 16 } }));
const { requestBodyLimit } = await import("./body-limit.ts");

const app = new Hono()
  .use("*", requestBodyLimit)
  .all("/api/v1/setup/restore/:id", async (c) => c.json({ bytes: (await c.req.arrayBuffer()).byteLength }))
  .all("/api/v1/other", async (c) => c.json({ bytes: (await c.req.arrayBuffer()).byteLength }))
  .all("/api/v1/agent/packages", async (c) => c.json({ bytes: (await c.req.arrayBuffer()).byteLength }));

const send = (method: string, path: string, size: number) =>
  app.request(path, {
    method,
    headers: { "content-length": String(size) },
    body: Buffer.alloc(size, 0x61),
  });

describe("request body limit", () => {
  it("lets a backup being restored be as large as configured (ADR 0046)", async () => {
    expect((await send("PUT", "/api/v1/setup/restore/abc", 2 * 1024 * 1024)).status).toBe(200);
    expect((await send("PUT", "/api/v1/setup/restore/abc", 16 * 1024 * 1024 + 1)).status).toBe(413);
    expect((await send("POST", "/api/v1/setup/restore", 1024 * 1024 + 1)).status).toBe(413);
  });

  it("keeps 1 MiB for every route and method", async () => {
    expect((await send("POST", "/api/v1/other", 1024 * 1024)).status).toBe(200);
    expect((await send("POST", "/api/v1/other", 1024 * 1024 + 1)).status).toBe(413);
    expect((await send("PUT", "/api/v1/other", 2 * 1024 * 1024)).status).toBe(413);
  });

  it("allows 8 MiB for the package list of a host agent only (ADR 0034)", async () => {
    expect((await send("POST", "/api/v1/agent/packages", 8 * 1024 * 1024)).status).toBe(200);
    expect((await send("POST", "/api/v1/agent/packages", 8 * 1024 * 1024 + 1)).status).toBe(413);
    expect((await send("POST", "/api/v1/agent/inventory", 2 * 1024 * 1024)).status).toBe(413);
  });
});
