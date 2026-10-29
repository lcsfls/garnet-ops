/**
 * The Docker socket proxy of the host agent (ADR 0034). It is the only part that holds the host's Docker socket, has no network, and
 * forwards nothing but `GET` and `HEAD` requests on a fixed list of read paths; everything else is answered 403 before it reaches
 * Docker. The agent and syft talk to Docker only through it, so neither can start, stop or create a container.
 */
import { chmod, mkdir, rm } from "node:fs/promises";
import { createServer, type IncomingMessage, request, type Server, type ServerResponse } from "node:http";
import { dirname } from "node:path";

/** Read paths, with or without an API version prefix such as `/v1.47`. Image names may contain slashes, colons and `@`. */
const ALLOWED = [
  /^\/_ping$/,
  /^\/version$/,
  /^\/info$/,
  /^\/containers\/json(\?[^#]*)?$/,
  /^\/images\/json(\?[^#]*)?$/,
  /^\/images\/[A-Za-z0-9._:@/%-]{1,600}\/json$/,
  /^\/images\/get\?[^#]*$/,
];

/** Whether the proxy forwards this request. */
export function allowed(method: string | undefined, url: string | undefined): boolean {
  if (method !== "GET" && method !== "HEAD") return false;
  if (!url || url.length > 2000 || url.includes("..")) return false;
  const path = url.replace(/^\/v\d{1,2}\.\d{1,3}(?=\/)/, "");
  return ALLOWED.some((re) => re.test(path));
}

export function createDockerProxy(dockerSocket: string): Server {
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    if (!allowed(req.method, req.url)) {
      res.writeHead(403, { "content-type": "application/json" });
      res.end('{"message":"refused by the GarnetOps agent proxy: read-only"}');
      req.resume();
      return;
    }
    const upstream = request(
      {
        socketPath: dockerSocket,
        method: req.method,
        path: req.url,
        // Only what a read needs; no body is ever forwarded.
        headers: { host: "docker", accept: req.headers.accept ?? "*/*" },
      },
      (answer) => {
        res.writeHead(answer.statusCode ?? 502, answer.headers);
        answer.pipe(res);
      },
    );
    upstream.on("error", () => {
      if (!res.headersSent) res.writeHead(502, { "content-type": "application/json" });
      res.end('{"message":"Docker did not answer"}');
    });
    req.on("close", () => upstream.destroy());
    upstream.end();
  });
}

/** Starts the proxy on `socket` (a volume shared with the agent container only). */
export async function serveProxy(dockerSocket: string, socket: string): Promise<Server> {
  await mkdir(dirname(socket), { recursive: true });
  await rm(socket, { force: true });
  const server = createDockerProxy(dockerSocket);
  await new Promise<void>((resolve) => server.listen(socket, resolve));
  // The volume is shared with the agent container alone; the agent runs as another user.
  await chmod(socket, 0o666);
  return server;
}
