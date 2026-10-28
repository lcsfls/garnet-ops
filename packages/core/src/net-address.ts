/**
 * The address policy for a host an admin types where the platform later connects to it, such as a
 * directory server (ADR 0020): a host name or an IP address, nothing else. Loopback, link-local
 * (cloud metadata), unspecified and multicast addresses are refused, and so are "numeric" names.
 */
import { isIP } from "node:net";
import { isForbiddenAddress } from "./notifications.ts";

export type AddressProblem = "empty" | "tooLong" | "characters" | "option" | "reserved" | "numeric";
export type AddressCheck =
  | { ok: true; address: string; kind: "ipv4" | "ipv6" | "hostname" }
  | { ok: false; problem: AddressProblem };

const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Checks and normalises the address of a server: a host name or an IP address, nothing else.
 *
 * Refused: anything that could be read as an ssh option (leading "-"), whitespace, user@,
 * brackets, zone ids, ports, paths; loopback, link-local (cloud metadata), unspecified and
 * multicast addresses; and "numeric" names such as `127.1` or `0x7f.1`, which resolvers turn
 * into an IPv4 address the checks above never saw.
 */
export function checkHostAddress(value: string): AddressCheck {
  const address = value.trim();
  if (address.length === 0) return { ok: false, problem: "empty" };
  if (address.length > 253) return { ok: false, problem: "tooLong" };
  if (address.startsWith("-")) return { ok: false, problem: "option" };
  if (!/^[A-Za-z0-9.:-]+$/.test(address)) return { ok: false, problem: "characters" };
  const kind = isIP(address);
  if (kind === 4 || kind === 6) {
    if (isForbiddenAddress(address)) return { ok: false, problem: "reserved" };
    return {
      ok: true,
      address: kind === 6 ? address.toLowerCase() : address,
      kind: kind === 6 ? "ipv6" : "ipv4",
    };
  }
  if (address.includes(":")) return { ok: false, problem: "characters" };
  const name = address.toLowerCase();
  const labels = name.split(".");
  if (!labels.every((l) => HOST_LABEL.test(l))) return { ok: false, problem: "characters" };
  const last = labels[labels.length - 1] as string;
  if (/^[0-9]+$/.test(last) || /^0x/.test(last)) return { ok: false, problem: "numeric" };
  if (name === "localhost" || name.endsWith(".localhost")) return { ok: false, problem: "reserved" };
  return { ok: true, address: name, kind: "hostname" };
}
