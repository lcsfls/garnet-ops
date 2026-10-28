/**
 * The worker's side of the scanner service (ADR 0028): asks it for an SBOM of a clone and for
 * grype's report on that SBOM, and writes both answers to files in the worker's private scratch
 * directory. Answers are hostile input like the repository they describe: they are bounded in size
 * here and parsed with schemas afterwards, as when the worker ran the tools itself.
 */
import { createReadStream, createWriteStream } from "node:fs";
import { stat } from "node:fs/promises";
import { request } from "node:http";
import { pipeline } from "node:stream/promises";
import { SCANNER_TIMEOUT_MS } from "./grype-run.ts";
import { byteLimit, MAX_DOCUMENT_BYTES } from "./scanner-service.ts";

/** The service did not answer: not running, not reachable, or no answer in time. */
export class ScannerUnavailableError extends Error {}

/** The service answered with an error code (`sbom_failed`, `scanner_failed`, `too_large`, ...). */
export class ScannerRequestError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(`scanner service: ${code}`);
    this.code = code;
  }
}

/** One run plus a margin for the transfer; a queue in the service never exceeds the worker's own concurrency. */
const REQUEST_TIMEOUT_MS = SCANNER_TIMEOUT_MS + 5 * 60_000;
const HEALTH_TIMEOUT_MS = 5_000;

type Body = { json: unknown } | { file: string };

/** Sends one request over the socket and streams a 200 answer into `outFile`. */
function call(socket: string, path: string, body: Body, outFile: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const signal = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
    const req = request({ socketPath: socket, path, method: "POST", signal }, (res) => {
      if (res.statusCode === 200) {
        pipeline(
          res,
          byteLimit(MAX_DOCUMENT_BYTES, () => new ScannerRequestError("too_large")),
          createWriteStream(outFile, { mode: 0o600 }),
        ).then(resolve, (error: Error) =>
          reject(error instanceof ScannerRequestError ? error : new ScannerUnavailableError(error.message)),
        );
        return;
      }
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (chunk: string) => {
        if (text.length < 1024) text += chunk;
      });
      res.on("end", () => {
        let code = `http_${res.statusCode}`;
        try {
          const parsed = JSON.parse(text) as { error?: unknown };
          if (typeof parsed.error === "string" && /^[a-z_]{1,40}$/.test(parsed.error)) code = parsed.error;
        } catch {
          // Not our service's answer; the status code says enough.
        }
        reject(new ScannerRequestError(code));
      });
      res.on("error", (error) => reject(new ScannerUnavailableError(error.message)));
    });
    req.on("error", (error) => reject(new ScannerUnavailableError(error.message)));
    if ("json" in body) {
      req.setHeader("content-type", "application/json");
      req.end(JSON.stringify(body.json));
    } else {
      req.setHeader("content-type", "application/json");
      stat(body.file).then(
        ({ size }) => {
          req.setHeader("content-length", size);
          pipeline(createReadStream(body.file), req).catch((error: Error) =>
            reject(new ScannerUnavailableError(error.message)),
          );
        },
        (error: Error) => {
          req.destroy();
          reject(error);
        },
      );
    }
  });
}

/**
 * Asks for the SBOM of a clone. `dir` is relative to the shared work directory
 * (`scan-XXXXXX/src`), which the service mounts at the same path as the worker.
 */
export function requestSbom(socket: string, dir: string, outFile: string): Promise<void> {
  return call(socket, "/v1/sbom", { json: { dir } }, outFile);
}

/** Asks for grype's report on an SBOM the service built before. */
export function requestMatch(socket: string, sbomFile: string, outFile: string): Promise<void> {
  return call(socket, "/v1/match", { file: sbomFile }, outFile);
}

/** The service's health answer: its release, or null when it does not answer. */
export function scannerHealth(socket: string): Promise<{ version: string | null } | null> {
  return new Promise((resolve) => {
    const req = request(
      {
        socketPath: socket,
        path: "/v1/health",
        method: "GET",
        signal: AbortSignal.timeout(HEALTH_TIMEOUT_MS),
      },
      (res) => {
        let text = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => {
          if (text.length < 1024) text += chunk;
        });
        res.on("end", () => {
          if (res.statusCode !== 200) return resolve(null);
          try {
            const { version } = JSON.parse(text) as { version?: unknown };
            resolve({ version: typeof version === "string" ? version.slice(0, 40) : null });
          } catch {
            resolve({ version: null });
          }
        });
        res.on("error", () => resolve(null));
      },
    );
    req.on("error", () => resolve(null));
    req.end();
  });
}
