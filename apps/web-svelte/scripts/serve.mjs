/**
 * Serves the built app the way the reverse proxy does (deploy/Caddyfile): files from `build/`, every other path answered
 * with `index.html`, `/api` forwarded to the API (server-sent events included), and the security headers with the
 * Content Security Policy from `build/csp.txt`. Used by the end-to-end suite and `pnpm preview`; never in production.
 *
 *   node scripts/serve.mjs --port 4173      GARNETOPS_API_URL=http://127.0.0.1:3000 (default)
 */
import { createReadStream, existsSync, readFileSync, statSync } from "node:fs";
import { createServer, request } from "node:http";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../build/", import.meta.url));
const portArg = process.argv.indexOf("--port");
const port = Number(portArg > 0 ? process.argv[portArg + 1] : (process.env.PORT ?? 4173));
const api = new URL(process.env.GARNETOPS_API_URL ?? "http://127.0.0.1:3000");
const policy = readFileSync(join(root, "csp.txt"), "utf8").trim();

const SECURITY_HEADERS = {
  "content-security-policy": policy,
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
};
const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".woff2": "font/woff2",
  ".woff": "font/woff",
  ".txt": "text/plain; charset=utf-8",
};

function proxy(req, res) {
  const upstream = request(
    {
      host: api.hostname,
      port: api.port,
      method: req.method,
      path: req.url,
      headers: { ...req.headers, "x-real-ip": req.socket.remoteAddress ?? "" },
    },
    (answer) => {
      res.writeHead(answer.statusCode ?? 502, answer.headers);
      res.flushHeaders();
      answer.pipe(res);
    },
  );
  upstream.on("error", () => {
    if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain" });
    res.end("Bad gateway");
  });
  req.pipe(upstream);
}

function file(path) {
  const target = normalize(join(root, decodeURIComponent(path)));
  if (!target.startsWith(root) || target.endsWith(sep)) return null;
  return existsSync(target) && statSync(target).isFile() ? target : null;
}

createServer((req, res) => {
  const { pathname } = new URL(req.url ?? "/", "http://localhost");
  if (pathname.startsWith("/api/")) return proxy(req, res);
  const found = file(pathname) ?? join(root, "index.html");
  const headers = {
    ...SECURITY_HEADERS,
    "content-type": TYPES[extname(found)] ?? "application/octet-stream",
    "cache-control": pathname.startsWith("/assets/") ? "public, max-age=31536000, immutable" : "no-cache",
  };
  res.writeHead(200, headers);
  createReadStream(found).pipe(res);
}).listen(port, "localhost", () => console.log(`serving build/ on http://localhost:${port}, API ${api.origin}`));
