/**
 * Writes the Content Security Policy of the built app to `build/csp.txt` (ADR 0027). SvelteKit puts the policy, with the
 * SHA-256 of its inline start script, into a `<meta>` tag of `build/index.html`. A meta tag cannot carry `frame-ancestors`,
 * so it is added here. The reverse proxy (deploy/Caddyfile) and `vite preview` send this file as the header; the build
 * fails if the policy is missing or allows anything inline.
 */
import { readFileSync, writeFileSync } from "node:fs";

const html = readFileSync(new URL("../build/index.html", import.meta.url), "utf8");
const match = html.match(/<meta http-equiv="content-security-policy" content="([^"]+)"/i);
if (!match) throw new Error("build/index.html has no Content-Security-Policy meta tag");
const policy = match[1].replaceAll("&#39;", "'").replaceAll("&quot;", '"').trim().replace(/;\s*$/, "");
if (/unsafe-inline|unsafe-eval/.test(policy)) throw new Error(`The policy allows inline code: ${policy}`);
// 'unsafe-hashes' only for style attributes, and only with explicit hashes (SvelteKit's screen-reader announcer).
for (const directive of policy.split(";").map((d) => d.trim())) {
  if (/'unsafe-hashes'/.test(directive) && !/^style-src-attr 'unsafe-hashes'( 'sha256-[A-Za-z0-9+/=]+')+$/.test(directive)) {
    throw new Error(`'unsafe-hashes' outside a hash-only style-src-attr: ${directive}`);
  }
}
if (!/script-src[^;]*'sha256-/.test(policy)) throw new Error(`The policy has no script hash: ${policy}`);
const inline = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>/g)].length;
if (inline !== 1) throw new Error(`Expected exactly one inline script in build/index.html, found ${inline}`);
writeFileSync(new URL("../build/csp.txt", import.meta.url), `${policy}; frame-ancestors 'none'\n`);
console.log(`csp.txt: ${policy}; frame-ancestors 'none'`);
