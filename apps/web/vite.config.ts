import tailwindcss from "@tailwindcss/vite";
import { tanstackRouter } from "@tanstack/router-plugin/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

/**
 * Content Security Policy of the built app (AGENTS.md rule 1). The production
 * build contains no inline scripts or styles, so 'self' is enough and neither
 * nonces nor 'unsafe-inline' are needed. The reverse proxy sends the same
 * header in production; `vite preview` sends it here so the build can be
 * tested under the real policy. The dev server cannot use it, because React
 * Fast Refresh injects an inline script.
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const securityHeaders = {
  "Content-Security-Policy": CONTENT_SECURITY_POLICY,
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
};

// Same-origin API in development: the browser only ever talks to the web origin (cookies, CSP connect-src 'self').
const api = {
  "/api": { target: process.env.GARNETOPS_API_URL ?? "http://127.0.0.1:3000", changeOrigin: false },
};

export default defineConfig({
  plugins: [tanstackRouter({ target: "react", autoCodeSplitting: true }), react(), tailwindcss()],
  server: { host: "localhost", port: 5173, strictPort: true, proxy: api },
  preview: { host: "localhost", port: 5173, strictPort: true, proxy: api, headers: securityHeaders },
  build: { sourcemap: false, assetsInlineLimit: 0 },
});
