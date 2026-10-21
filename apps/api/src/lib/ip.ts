/**
 * Client address for the audit log. Only meaningful behind our own reverse
 * proxy, which overwrites these headers; the API binds to loopback by default.
 */
export function clientIp(headers: Headers): string | null {
  // Only meaningful behind our own reverse proxy (Caddy), which overwrites this header.
  return headers.get("x-real-ip") ?? headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? null;
}
