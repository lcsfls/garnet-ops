import { checkHostAddress } from "./net-address.ts";

/**
 * The address policy for directory servers (ADR 0020).
 * Loopback, link-local (cloud metadata), unspecified and multicast addresses and numeric
 * oddities such as `127.1` are refused; private networks are allowed, because a directory
 * normally lives in one. Returns the normalised host, or null.
 */
export function directoryHostPolicy(host: string): string | null {
  const checked = checkHostAddress(host);
  return checked.ok ? checked.address : null;
}
