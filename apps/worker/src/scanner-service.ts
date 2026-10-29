/**
 * The scanner service (ADR 0028): runs syft and grype for the worker in a container of its own,
 * which has no network, no vault key, no database and only read access to the clones.
 *
 * It speaks HTTP over a Unix socket on a volume shared with the worker:
 *
 *   GET  /v1/health              200 and `{"ok": true, "version": ...}` (the image's release) when up
 *   POST /v1/sbom   {"dir": ...}  syft's SBOM (syft-json) of a clone below the work directory
 *   POST /v1/match  <SBOM>        grype's JSON report for the SBOM in the request body
 *   POST /v1/match-purls <list>   grype's JSON report for package URLs, one per line (early warnings, ADR 0029)
 *
 * Errors answer with a status and `{"error": "<code>"}`. Nothing a tool prints is returned or logged:
 * a scanned repository is hostile input, and so is everything syft and grype say about it.
 */
import { createReadStream, createWriteStream } from "node:fs";
import { mkdtemp, realpath, rm, stat, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { runGrype } from "./grype-run.ts";
import { buildSbom } from "./syft.ts";

/** Upper bound for an SBOM or a report in either direction. */
export const MAX_DOCUMENT_BYTES = 512 * 1024 * 1024;
/** Upper bound for a list of package URLs and for one of them. */
export const MAX_PURL_LIST_BYTES = 16 * 1024 * 1024;
const MAX_PURL_LENGTH = 1000;

/**
 * A package URL list as grype reads it, or null when a line is not one: `pkg:` and printable ASCII
 * only, so nothing in it can be taken for an option or a different input.
 */
export function purlList(text: string): string | null {
  const lines = text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length === 0) return null;
  for (const line of lines) {
    if (!line.startsWith("pkg:") || line.length > MAX_PURL_LENGTH || !/^[\x21-\x7e]+$/.test(line))
      return null;
  }
  return `${lines.join("\n")}\n`;
}
const MAX_REQUEST_JSON_BYTES = 4 * 1024;

/** A clone as the worker names it: `<scan directory>/src` directly below the work directory. */
const CLONE_DIR = /^scan-[A-Za-z0-9]{6}\/src$/;

export interface ScannerServiceConfig {
  /** The shared volume with the clones, mounted read-only. */
  workDir: string;
  grypeBin: string;
  syftBin: string;
  grypeDbDir: string;
  /** How many syft or grype runs at once; more requests wait. */
  concurrency: number;
  /** The release of this image, told to the worker so that it can tell a mismatch. */
  version: string | null;
}

class RequestError extends Error {
  readonly status: number;
  constructor(status: number, code: string) {
    super(code);
    this.status = status;
  }
}

/** Counts bytes and fails the stream once there are more than `limit`. */
export function byteLimit(limit: number, onExceeded: () => Error): Transform {
  let seen = 0;
  return new Transform({
    transform(chunk: Buffer, _encoding, done) {
      seen += chunk.length;
      if (seen > limit) done(onExceeded());
      else done(null, chunk);
    },
  });
}

/** A counting semaphore: at most `slots` holders at once, the others wait in order. */
function semaphore(slots: number) {
  let free = slots;
  const waiting: (() => void)[] = [];
  return async <T>(work: () => Promise<T>): Promise<T> => {
    if (free > 0) free--;
    else await new Promise<void>((resolve) => waiting.push(resolve));
    try {
      return await work();
    } finally {
      const next = waiting.shift();
      if (next) next();
      else free++;
    }
  };
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (body.length > MAX_REQUEST_JSON_BYTES) throw new RequestError(413, "too_large");
  }
  try {
    return JSON.parse(body);
  } catch {
    throw new RequestError(400, "bad_request");
  }
}

/** The clone a request names, resolved inside the work directory, or a 400. */
async function cloneDir(workDir: string, value: unknown): Promise<string> {
  if (typeof value !== "string" || !CLONE_DIR.test(value)) throw new RequestError(400, "bad_request");
  const root = await realpath(workDir);
  const dir = await realpath(join(root, value)).catch(() => {
    throw new RequestError(404, "not_found");
  });
  if (!dir.startsWith(root + sep) || !(await stat(dir)).isDirectory())
    throw new RequestError(400, "bad_request");
  return dir;
}

async function sendFile(res: ServerResponse, file: string): Promise<void> {
  const { size } = await stat(file);
  if (size > MAX_DOCUMENT_BYTES) throw new RequestError(422, "too_large");
  res.writeHead(200, { "content-type": "application/json", "content-length": size });
  await pipeline(createReadStream(file), res);
}

export function createScannerService(config: ScannerServiceConfig): Server {
  const limited = semaphore(config.concurrency);

  /** Runs `work` with a scratch directory of its own in the service's tmpfs, removed afterwards. */
  const withScratch = <T>(work: (dir: string) => Promise<T>) =>
    limited(async () => {
      const dir = await mkdtemp(join(tmpdir(), "run-"));
      try {
        return await work(dir);
      } finally {
        await rm(dir, { recursive: true, force: true }).catch(() => {});
      }
    });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method === "GET" && req.url === "/v1/health") {
      res
        .writeHead(200, { "content-type": "application/json" })
        .end(JSON.stringify({ ok: true, version: config.version }));
      return;
    }
    if (req.method === "POST" && req.url === "/v1/sbom") {
      const body = (await readJson(req)) as { dir?: unknown } | null;
      const dir = await cloneDir(config.workDir, body?.dir);
      await withScratch(async (scratch) => {
        const sbom = await buildSbom(config.syftBin, dir, scratch).catch((error: Error) => {
          console.error(`scanner: syft: ${error.message}`);
          throw new RequestError(422, "sbom_failed");
        });
        await sendFile(res, sbom);
      });
      return;
    }
    if (req.method === "POST" && req.url === "/v1/match-purls") {
      let text = "";
      for await (const chunk of req) {
        text += chunk;
        if (text.length > MAX_PURL_LIST_BYTES) throw new RequestError(413, "too_large");
      }
      const list = purlList(text);
      if (!list) throw new RequestError(400, "bad_request");
      await withScratch(async (scratch) => {
        const file = join(scratch, "input.purls");
        await writeFile(file, list, { mode: 0o600 });
        const report = await runGrype(config.grypeBin, config.grypeDbDir, `purl:${file}`, scratch).catch(
          (error: Error) => {
            console.error(`scanner: grype: ${error.message}`);
            throw new RequestError(422, "scanner_failed");
          },
        );
        await sendFile(res, report);
      });
      return;
    }
    if (req.method === "POST" && req.url === "/v1/match") {
      await withScratch(async (scratch) => {
        const sbom = join(scratch, "input.syft.json");
        await pipeline(
          req,
          byteLimit(MAX_DOCUMENT_BYTES, () => new RequestError(413, "too_large")),
          createWriteStream(sbom, { mode: 0o600 }),
        );
        const report = await runGrype(config.grypeBin, config.grypeDbDir, `sbom:${sbom}`, scratch).catch(
          (error: Error) => {
            console.error(`scanner: grype: ${error.message}`);
            throw new RequestError(422, "scanner_failed");
          },
        );
        await sendFile(res, report);
      });
      return;
    }
    throw new RequestError(404, "not_found");
  }

  return createServer((req, res) => {
    handle(req, res).catch((error: unknown) => {
      const known = error instanceof RequestError;
      if (!known)
        console.error(`scanner: ${(error as Error)?.name ?? "error"}: ${(error as Error)?.message}`);
      if (res.headersSent) {
        res.destroy();
        return;
      }
      res
        .writeHead(known ? error.status : 500, { "content-type": "application/json", connection: "close" })
        .end(JSON.stringify({ error: known ? error.message : "unexpected" }));
      // Whatever the client still sends is not read.
      req.resume();
    });
  });
}
