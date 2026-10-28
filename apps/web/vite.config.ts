import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import adapter from "@sveltejs/adapter-static";
import { sveltekit } from "@sveltejs/kit/vite";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

/**
 * `vite preview` serves the built app under the same headers as the reverse proxy, so the end-to-end suite tests the
 * real Content Security Policy (with the hash of SvelteKit's start script, `scripts/csp.mjs`). The dev server cannot use
 * it: hot module replacement injects scripts.
 */
function securityHeaders(): Record<string, string> {
  const file = new URL("./build/csp.txt", import.meta.url);
  const policy = existsSync(file)
    ? readFileSync(file, "utf8").trim()
    : "default-src 'self'; frame-ancestors 'none'";
  return {
    "Content-Security-Policy": policy,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  };
}

/**
 * The Content Security Policy of the web app (AGENTS.md rule 1, ADR 0027). SvelteKit starts the app with one inline
 * script; in hash mode it adds that script's SHA-256 to `script-src`, so `'unsafe-inline'` is never needed. The policy
 * lands in a `<meta>` tag of the built page, and `scripts/csp.mjs` copies it, plus the directive a meta tag cannot carry
 * (`frame-ancestors`), into `build/csp.txt` for the reverse proxy and `vite preview`.
 */
/**
 * SvelteKit's root component renders a visually hidden live region for screen readers (`#svelte-announcer`) with a fixed
 * `style` attribute. `style-src-attr 'unsafe-hashes'` with the SHA-256 of exactly that value allows this one attribute and
 * nothing else; no script, no `<style>` element, no other attribute. The hash is computed from SvelteKit's own source,
 * so an update of SvelteKit cannot silently break it, and `scripts/csp.mjs` checks the build against it.
 */
function announcerStyleHashes(): string[] {
  const kit = dirname(createRequire(import.meta.url).resolve("@sveltejs/kit/package.json"));
  const root = readFileSync(join(kit, "src/runtime/components/root.svelte"), "utf8");
  const styles = [...root.matchAll(/\sstyle="([^"]*)"/g)].map((m) => m[1] ?? "");
  if (styles.length !== 1)
    throw new Error(`Expected one style attribute in SvelteKit's root component, found ${styles.length}`);
  return styles.map((style) => `sha256-${createHash("sha256").update(style).digest("base64")}`);
}

const CSP_DIRECTIVES = {
  "default-src": ["self"],
  "script-src": ["self"],
  "style-src": ["self"],
  "style-src-attr": ["unsafe-hashes", ...announcerStyleHashes()],
  "img-src": ["self"],
  "font-src": ["self"],
  "connect-src": ["self"],
  "object-src": ["none"],
  "base-uri": ["none"],
  "form-action": ["self"],
} as const;

// Same-origin API in development: the browser only ever talks to the web origin (cookies, CSP connect-src 'self').
const api = {
  "/api": { target: process.env.GARNETOPS_API_URL ?? "http://127.0.0.1:3000", changeOrigin: false },
};

export default defineConfig(({ command }) => ({
  plugins: [
    tailwindcss(),
    sveltekit({
      // A single-page app: no server in the web image; Caddy serves `build/` and answers unknown paths with index.html.
      adapter: adapter({ pages: "build", assets: "build", fallback: "index.html", strict: true }),
      csp: { mode: "hash", directives: CSP_DIRECTIVES as never },
      // Hashed file names under /assets, as before: the reverse proxy caches them for a year.
      appDir: "assets",
      // Never inline CSS: every style comes from 'self'.
      inlineStyleThreshold: 0,
      output: { bundleStrategy: "split" },
      version: { pollInterval: 0 },
    }),
  ],
  server: { host: "localhost", port: 5173, strictPort: true, proxy: api },
  preview: {
    host: "localhost",
    port: 5173,
    strictPort: true,
    proxy: api,
    headers: command === "serve" ? securityHeaders() : {},
  },
  build: { sourcemap: false, assetsInlineLimit: 0 },
}));
