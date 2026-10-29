/**
 * Fixtures for the external exposure tests (ADR 0023), never used by production code: throw-away certificates made with openssl at
 * test time (a valid one, one that expires in a few days, one that expired in 2020), a fake resolver, and local TCP and TLS servers.
 * Nothing here looks like a real credential: the certificates are public test certificates for example.com names, made when the test
 * runs, and their private keys never leave the temporary directory.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { createServer as createNetServer, type Server, type Socket } from "node:net";
import { join } from "node:path";
import { createServer as createTlsServer, type TlsOptions } from "node:tls";
import type { DnsLike } from "../src/exposure-net.ts";

export interface Pem {
  key: string;
  cert: string;
}

export const SITE = "site.example.com";

function openssl(args: string[]): void {
  execFileSync("openssl", args, { stdio: "ignore" });
}

/** A certificate for `names`, valid for `days` days from now. */
export function selfSigned(dir: string, name: string, names: string[], days: number): Pem {
  const keyFile = join(dir, `${name}.key`);
  const certFile = join(dir, `${name}.pem`);
  openssl([
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:prime256v1",
    "-nodes",
    "-days",
    String(days),
    "-subj",
    `/CN=${names[0]}`,
    "-addext",
    `subjectAltName=${names.map((n) => `DNS:${n}`).join(",")}`,
    "-keyout",
    keyFile,
    "-out",
    certFile,
  ]);
  return { key: readFileSync(keyFile, "utf8"), cert: readFileSync(certFile, "utf8") };
}

/** A self-signed certificate that was valid for one day in January 2020 (a real expired certificate, no clock tricks). */
export function expiredCert(dir: string, name: string): Pem {
  const base = join(dir, `${name}-ca`);
  writeFileSync(
    `${base}.cnf`,
    `[ca]
default_ca = CA_default
[CA_default]
database = ${base}.index
new_certs_dir = ${dir}
serial = ${base}.serial
default_md = sha256
policy = policy_any
unique_subject = no
copy_extensions = copy
x509_extensions = v3
[policy_any]
commonName = supplied
[v3]
subjectAltName = DNS:${name}
[req]
distinguished_name = dn
prompt = no
[dn]
CN = ${name}
`,
  );
  writeFileSync(`${base}.index`, "");
  writeFileSync(`${base}.serial`, "01\n");
  const keyFile = `${base}.key`;
  const csr = `${base}.csr`;
  const certFile = `${base}.pem`;
  openssl([
    "req",
    "-new",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:prime256v1",
    "-nodes",
    "-keyout",
    keyFile,
    "-out",
    csr,
    "-config",
    `${base}.cnf`,
  ]);
  openssl([
    "ca",
    "-selfsign",
    "-keyfile",
    keyFile,
    "-in",
    csr,
    "-out",
    certFile,
    "-config",
    `${base}.cnf`,
    "-startdate",
    "20200101000000Z",
    "-enddate",
    "20200102000000Z",
    "-batch",
    "-notext",
  ]);
  return { key: readFileSync(keyFile, "utf8"), cert: readFileSync(certFile, "utf8") };
}

export function haveOpenssl(): boolean {
  try {
    execFileSync("openssl", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* A fake resolver                                                             */
/* -------------------------------------------------------------------------- */

export interface Records {
  a?: string[];
  aaaa?: string[];
  cname?: string[];
  mx?: { priority: number; exchange: string }[];
  ns?: string[];
  caa?: { critical: number; [tag: string]: string | number | undefined }[];
  txt?: string[][];
  ptr?: string[];
  /** Lookups of these types fail like a broken resolver (SERVFAIL). */
  fail?: ("a" | "aaaa" | "cname" | "mx" | "ns" | "caa" | "txt")[];
}

export type FakeDns = DnsLike & {
  zone: Record<string, Records>;
  /** Every name that was asked for, with the record type. */
  queries: string[];
};

const noData = () => Object.assign(new Error("no data"), { code: "ENODATA" });
const servfail = () => Object.assign(new Error("servfail"), { code: "ESERVFAIL" });

/** A resolver that answers from a table. `zone` can be changed between lookups. */
export function fakeDns(zone: Record<string, Records>): FakeDns {
  const queries: string[] = [];
  const answer = <T>(
    type: NonNullable<Records["fail"]>[number],
    name: string,
    pick: (r: Records) => T[] | undefined,
  ): Promise<T[]> => {
    queries.push(`${type}:${name}`);
    const records = zone[name.toLowerCase()];
    if (records?.fail?.includes(type)) return Promise.reject(servfail());
    const found = records ? pick(records) : undefined;
    return found && found.length > 0 ? Promise.resolve(found) : Promise.reject(noData());
  };
  return {
    zone,
    queries,
    resolve4: (name) => answer("a", name, (r) => r.a),
    resolve6: (name) => answer("aaaa", name, (r) => r.aaaa),
    resolveCname: (name) => answer("cname", name, (r) => r.cname),
    resolveMx: (name) => answer("mx", name, (r) => r.mx),
    resolveNs: (name) => answer("ns", name, (r) => r.ns),
    resolveCaa: (name) => answer("caa", name, (r) => r.caa),
    resolveTxt: (name) => answer("txt", name, (r) => r.txt),
    reverse: (address) => {
      queries.push(`ptr:${address}`);
      const found = Object.values(zone).find((r) => r.a?.includes(address) || r.aaaa?.includes(address))?.ptr;
      return found ? Promise.resolve(found) : Promise.reject(noData());
    },
  };
}

/* -------------------------------------------------------------------------- */
/* Local servers                                                               */
/* -------------------------------------------------------------------------- */

export interface Listener {
  server: Server;
  port: number;
  /** Connections accepted so far. */
  connections: number;
  /** Every byte a client wrote to the port. */
  received: Buffer[];
  close(): Promise<void>;
}

export const bytesReceived = (l: Listener): number => l.received.reduce((n, b) => n + b.length, 0);

/** A TCP server on loopback. `onConnect` decides what the service says first. */
export async function tcpListener(
  onConnect: (socket: Socket) => void = () => {},
  shared?: { current: number; max: number },
): Promise<Listener> {
  const sockets = new Set<Socket>();
  const listener: Listener = {
    server: createNetServer((socket) => {
      listener.connections += 1;
      sockets.add(socket);
      if (shared) {
        shared.current += 1;
        shared.max = Math.max(shared.max, shared.current);
      }
      socket.on("data", (chunk) => listener.received.push(chunk));
      socket.on("error", () => {});
      socket.on("close", () => {
        sockets.delete(socket);
        if (shared) shared.current -= 1;
      });
      onConnect(socket);
    }),
    port: 0,
    connections: 0,
    received: [],
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => listener.server.close(() => resolve()));
    },
  };
  await new Promise<void>((resolve) => listener.server.listen(0, "127.0.0.1", resolve));
  listener.port = (listener.server.address() as { port: number }).port;
  return listener;
}

/** A port nothing listens on. */
export async function closedPort(): Promise<number> {
  const listener = await tcpListener();
  const { port } = listener;
  await listener.close();
  return port;
}

/** A TLS server (any protocol version the options allow). Counts handshakes; closes the connection after the handshake. */
export async function tlsListener(options: TlsOptions): Promise<Listener> {
  const sockets = new Set<Socket>();
  const listener: Listener = {
    server: createTlsServer(options, (socket) => {
      listener.connections += 1;
      socket.on("data", (chunk) => listener.received.push(chunk));
      socket.on("error", () => {});
      socket.end();
    }) as unknown as Server,
    port: 0,
    connections: 0,
    received: [],
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => listener.server.close(() => resolve()));
    },
  };
  await new Promise<void>((resolve) => listener.server.listen(0, "127.0.0.1", resolve));
  listener.port = (listener.server.address() as { port: number }).port;
  return listener;
}

/** The types of the TLS records in a byte stream (22 handshake, 23 application data, ...). */
export function tlsRecordTypes(bytes: Buffer): number[] {
  const types: number[] = [];
  let offset = 0;
  while (offset + 5 <= bytes.length) {
    types.push(bytes[offset] as number);
    offset += 5 + bytes.readUInt16BE(offset + 3);
  }
  return types;
}
