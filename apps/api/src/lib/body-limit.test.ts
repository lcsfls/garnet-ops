import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { requestBodyLimit } from "./body-limit.ts";

const app = new Hono()
  .use("*", requestBodyLimit)
  .all("/api/v1/attacks/geoip/:kind", async (c) => c.json({ bytes: (await c.req.arrayBuffer()).byteLength }))
  .all("/api/v1/other", async (c) => c.json({ bytes: (await c.req.arrayBuffer()).byteLength }));

const send = (method: string, path: string, size: number) =>
  app.request(path, {
    method,
    headers: { "content-length": String(size) },
    body: Buffer.alloc(size, 0x61),
  });

describe("request body limit", () => {
  it("keeps 1 MiB for everything but the GeoIP upload", async () => {
    expect((await send("POST", "/api/v1/other", 1024 * 1024)).status).toBe(200);
    expect((await send("POST", "/api/v1/other", 1024 * 1024 + 1)).status).toBe(413);
    expect((await send("PUT", "/api/v1/other", 2 * 1024 * 1024)).status).toBe(413);
  });

  it("lets only a PUT of a country or ASN file be larger", async () => {
    const big = 3 * 1024 * 1024;
    expect(await (await send("PUT", "/api/v1/attacks/geoip/country", big)).json()).toEqual({ bytes: big });
    expect((await send("PUT", "/api/v1/attacks/geoip/asn", big)).status).toBe(200);
    expect((await send("POST", "/api/v1/attacks/geoip/country", big)).status).toBe(413);
    expect((await send("PUT", "/api/v1/attacks/geoip/city", big)).status).toBe(413);
    expect((await send("PUT", "/api/v1/attacks/geoip/country/extra", big)).status).toBe(413);
  });
});
