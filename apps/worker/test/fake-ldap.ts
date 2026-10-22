/**
 * A small LDAP server for tests (ADR 0020), built on the message classes of ldapts, so nothing
 * but the client library itself is needed and nothing leaves the machine. It speaks just enough of
 * LDAP v3 for directory sign-in: simple bind, search (base, one, sub), the StartTLS extended
 * operation, unbind and the filters ldapts can parse, including Active Directory's matching
 * rule in chain for nested groups. It keeps a log of what it saw (never a password), so a test
 * can prove what the client did and did not send.
 *
 * It is a test double and has the failings of one: no schema, no access control, and attribute
 * values are compared as case-insensitive text (distinguished names as names).
 */
import { createServer as createNetServer, type Server as NetServer, type Socket } from "node:net";
import {
  createSecureContext,
  createServer as createTlsServer,
  type TLSSocket,
  TLSSocket as TlsSocketClass,
} from "node:tls";
import { isUnderDn, normalizeDn, parseDn } from "@garnetops/core/directory";
import {
  AndFilter,
  Attribute,
  BerReader,
  BerWriter,
  BindRequest,
  EqualityFilter,
  ExtendedRequest,
  ExtensibleFilter,
  type Filter,
  NotFilter,
  OrFilter,
  PresenceFilter,
  ProtocolOperation,
  SearchRequest,
  SubstringFilter,
} from "ldapts";

export interface FakeEntry {
  dn: string;
  attributes: Record<string, (string | Buffer)[]>;
}

export interface FakeLdapOptions {
  entries: FakeEntry[];
  /** Passwords for simple binds, by DN. */
  passwords: Record<string, string>;
  /** `ldaps`: TLS from the start. `ldap`: plain, with StartTLS if `tls` is given. */
  mode: "ldaps" | "ldap";
  tls?: { key: string; cert: string };
  /** Answer a bind with an empty password as a success, the way many servers treat an unauthenticated bind. */
  allowUnauthenticatedBind?: boolean;
  /** Answer an anonymous bind (no name, no password) as a success. */
  allowAnonymousBind?: boolean;
  /** Refuse every bind and search on a connection that is not encrypted (confidentialityRequired). */
  requireTls?: boolean;
  /** Answer StartTLS with this result code instead of success (for example 2). */
  startTlsStatus?: number;
  /** Listen on this port instead of a free one. */
  port?: number;
  /** Return matching entries from anywhere, whatever base and scope the search names (a server that lies). */
  ignoreScope?: boolean;
}

export interface Seen {
  op: "bind" | "search" | "starttls" | "unbind";
  /** Whether the connection was encrypted when the operation arrived. */
  tls: boolean;
  dn?: string;
  /** Bind: how long the password was (the value is never kept). */
  passwordLength?: number;
  /** Search: the base, scope and filter as the server received them. */
  base?: string;
  scope?: string;
  filter?: string;
  sizeLimit?: number;
  attributes?: string[];
  connection: number;
}

const STATUS = {
  success: 0,
  sizeLimitExceeded: 4,
  unwillingToPerform: 53,
  confidentialityRequired: 13,
  noSuchObject: 32,
  invalidCredentials: 49,
  protocolError: 2,
} as const;

const START_TLS_OID = "1.3.6.1.4.1.1466.20037";
const CHAIN_RULE = "1.2.840.113556.1.4.1941";

function result(
  messageId: number,
  tag: number,
  status: number,
  message = "",
  extra?: (w: BerWriter) => void,
): Buffer {
  const w = new BerWriter();
  w.startSequence();
  w.writeInt(messageId);
  w.startSequence(tag);
  w.writeEnumeration(status);
  w.writeString("");
  w.writeString(message);
  extra?.(w);
  w.endSequence();
  w.endSequence();
  return w.buffer;
}

function entryMessage(messageId: number, entry: FakeEntry, wanted: string[]): Buffer {
  const w = new BerWriter();
  w.startSequence();
  w.writeInt(messageId);
  w.startSequence(ProtocolOperation.LDAP_RES_SEARCH_ENTRY);
  w.writeString(entry.dn);
  w.startSequence();
  const all = wanted.length === 0 || wanted.includes("*");
  const none = wanted.length === 1 && wanted[0] === "1.1";
  for (const [type, values] of Object.entries(entry.attributes)) {
    if (none || (!all && !wanted.includes(type.toLowerCase()))) continue;
    // Binary attributes go out as raw bytes; the client decides how to read them.
    new Attribute({ type, values: values as string[] | Buffer[] }).write(w);
  }
  w.endSequence();
  w.endSequence();
  w.endSequence();
  return w.buffer;
}

/** The first complete LDAP message in `buffer`, and what is left. */
function takeMessage(buffer: Buffer): { message: Buffer; rest: Buffer } | null {
  if (buffer.length < 2 || buffer[0] !== 0x30) return null;
  let length = buffer[1] as number;
  let header = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (buffer.length < 2 + count) return null;
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + (buffer[2 + i] as number);
    header = 2 + count;
  }
  if (buffer.length < header + length) return null;
  return { message: buffer.subarray(0, header + length), rest: buffer.subarray(header + length) };
}

const lower = (value: string | Buffer) =>
  (Buffer.isBuffer(value) ? value.toString("hex") : value).toLowerCase();

export class FakeLdapServer {
  readonly seen: Seen[] = [];
  connections = 0;
  private server: NetServer | undefined;
  private readonly options: FakeLdapOptions;
  private readonly sockets = new Set<Socket>();
  /** Makes searches never answer (for timeout tests). */
  hangSearches = false;
  /** Makes the next searches answer with this status instead of results. */
  failSearchesWith: number | null = null;
  /** Limits {@link failSearchesWith} to searches of this scope (for example only the group searches, which are `base`). */
  failScope: string | null = null;
  /** Changes at run time: the entries and passwords. */
  entries: FakeEntry[];
  passwords: Record<string, string>;

  constructor(options: FakeLdapOptions) {
    this.options = options;
    this.entries = options.entries;
    this.passwords = Object.fromEntries(
      Object.entries(options.passwords).map(([dn, pw]) => [normalizeDn(dn) ?? dn, pw]),
    );
  }

  get port(): number {
    const address = this.server?.address();
    if (!address || typeof address === "string") throw new Error("the server is not listening");
    return address.port;
  }

  async start(): Promise<void> {
    const { mode, tls } = this.options;
    if (mode === "ldaps") {
      if (!tls) throw new Error("ldaps needs a certificate");
      this.server = createTlsServer({ key: tls.key, cert: tls.cert, minVersion: "TLSv1.2" }, (socket) =>
        this.accept(socket, true),
      );
    } else {
      this.server = createNetServer((socket) => this.accept(socket, false));
    }
    await new Promise<void>((resolve) => this.server?.listen(this.options.port ?? 0, "127.0.0.1", resolve));
  }

  /** Switches the certificate the TLS server presents (ldaps mode and StartTLS). */
  setCertificate(tls: { key: string; cert: string }): void {
    this.options.tls = tls;
    (this.server as unknown as { setSecureContext?: (o: object) => void }).setSecureContext?.(tls);
  }

  async stop(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    await new Promise<void>((resolve) => (this.server ? this.server.close(() => resolve()) : resolve()));
  }

  reset(): void {
    this.seen.length = 0;
    this.hangSearches = false;
    this.failSearchesWith = null;
    this.failScope = null;
  }

  private accept(initial: Socket | TLSSocket, encrypted: boolean): void {
    const id = ++this.connections;
    this.sockets.add(initial);
    initial.on("close", () => this.sockets.delete(initial));
    initial.on("error", () => {});
    let socket: Socket | TLSSocket = initial;
    let tls = encrypted;
    let buffer: Buffer = Buffer.alloc(0);

    const onData = (data: Buffer) => {
      buffer = Buffer.concat([buffer, data]);
      for (;;) {
        const next = takeMessage(buffer);
        if (!next) return;
        buffer = next.rest as Buffer;
        const upgraded = this.handle(next.message, socket, tls, id);
        if (upgraded) {
          // StartTLS: the next bytes on this socket are a TLS handshake.
          initial.removeListener("data", onData);
          const tlsOptions = this.options.tls;
          if (!tlsOptions) return;
          const secure = new TlsSocketClass(initial, {
            isServer: true,
            secureContext: createSecureContext({
              key: tlsOptions.key,
              cert: tlsOptions.cert,
              minVersion: "TLSv1.2",
            }),
          });
          secure.on("error", () => {});
          this.sockets.add(secure);
          secure.on("close", () => this.sockets.delete(secure));
          socket = secure;
          tls = true;
          buffer = Buffer.alloc(0);
          secure.on("data", onData);
          return;
        }
      }
    };
    initial.on("data", onData);
  }

  /** Handles one message. Returns true when the connection must now be upgraded to TLS. */
  private handle(message: Buffer, socket: Socket | TLSSocket, tls: boolean, connection: number): boolean {
    const reader = new BerReader(message);
    reader.readSequence();
    const messageId = reader.readInt() as number;
    const operation = reader.readSequence() as number;
    const send = (buf: Buffer) => {
      if (!socket.destroyed) socket.write(buf);
    };

    if (operation === ProtocolOperation.LDAP_REQ_UNBIND) {
      this.seen.push({ op: "unbind", tls, connection });
      socket.end();
      return false;
    }

    if (operation === ProtocolOperation.LDAP_REQ_EXTENSION) {
      const request = new ExtendedRequest({ messageId });
      request.parse(reader, []);
      if (request.oid !== START_TLS_OID) {
        send(result(messageId, ProtocolOperation.LDAP_RES_EXTENSION, STATUS.protocolError));
        return false;
      }
      this.seen.push({ op: "starttls", tls, connection });
      const status =
        this.options.startTlsStatus ?? (this.options.tls ? STATUS.success : STATUS.unwillingToPerform);
      send(
        result(messageId, ProtocolOperation.LDAP_RES_EXTENSION, status, "", (w) => {
          if (status === 0) w.writeString(START_TLS_OID, 0x8a);
        }),
      );
      return status === 0 && !tls;
    }

    if (operation === ProtocolOperation.LDAP_REQ_BIND) {
      const request = new BindRequest({ messageId });
      request.parse(reader, []);
      this.seen.push({
        op: "bind",
        tls,
        dn: request.dn,
        passwordLength: request.password.length,
        connection,
      });
      if (this.options.requireTls && !tls) {
        send(
          result(messageId, ProtocolOperation.LDAP_RES_BIND, STATUS.confidentialityRequired, "TLS required"),
        );
        return false;
      }
      let status: number = STATUS.invalidCredentials;
      if (request.dn === "" && request.password === "") {
        status = this.options.allowAnonymousBind ? STATUS.success : STATUS.unwillingToPerform;
      } else if (request.password === "") {
        // RFC 4513, 5.1.2: a name with an empty password is an "unauthenticated bind".
        status = this.options.allowUnauthenticatedBind ? STATUS.success : STATUS.unwillingToPerform;
      } else {
        const expected = this.passwords[normalizeDn(request.dn) ?? "\u0000"];
        if (expected !== undefined && expected === request.password) status = STATUS.success;
      }
      send(result(messageId, ProtocolOperation.LDAP_RES_BIND, status));
      return false;
    }

    if (operation === ProtocolOperation.LDAP_REQ_SEARCH) {
      const request = new SearchRequest({ messageId, filter: undefined as unknown as Filter });
      request.parse(reader, []);
      this.seen.push({
        op: "search",
        tls,
        base: request.baseDN,
        scope: request.scope,
        filter: request.filter.toString(),
        sizeLimit: request.sizeLimit,
        attributes: request.attributes,
        connection,
      });
      if (this.options.requireTls && !tls) {
        send(
          result(
            messageId,
            ProtocolOperation.LDAP_RES_SEARCH,
            STATUS.confidentialityRequired,
            "TLS required",
          ),
        );
        return false;
      }
      if (this.hangSearches) return false;
      if (this.failSearchesWith !== null && (this.failScope === null || this.failScope === request.scope)) {
        send(result(messageId, ProtocolOperation.LDAP_RES_SEARCH, this.failSearchesWith));
        return false;
      }
      const baseExists = this.entries.some((e) => normalizeDn(e.dn) === normalizeDn(request.baseDN));
      if (!baseExists) {
        send(result(messageId, ProtocolOperation.LDAP_RES_SEARCH, STATUS.noSuchObject));
        return false;
      }
      const matches = this.entries.filter(
        (entry) =>
          (this.options.ignoreScope || inScope(entry.dn, request)) && this.matches(request.filter, entry),
      );
      const limit = request.sizeLimit > 0 ? request.sizeLimit : Number.POSITIVE_INFINITY;
      for (const entry of matches.slice(0, limit)) send(entryMessage(messageId, entry, request.attributes));
      send(
        result(
          messageId,
          ProtocolOperation.LDAP_RES_SEARCH,
          matches.length > limit ? STATUS.sizeLimitExceeded : STATUS.success,
        ),
      );
      return false;
    }

    send(
      result(
        messageId,
        ProtocolOperation.LDAP_RES_SEARCH,
        STATUS.unwillingToPerform,
        "read-only test server",
      ),
    );
    return false;
  }

  private values(entry: FakeEntry, attribute: string): (string | Buffer)[] {
    const wanted = attribute.toLowerCase();
    for (const [key, values] of Object.entries(entry.attributes)) {
      if (key.toLowerCase() === wanted) return values;
    }
    return [];
  }

  private byDn(dn: string): FakeEntry | undefined {
    const n = normalizeDn(dn);
    return n === null ? undefined : this.entries.find((e) => normalizeDn(e.dn) === n);
  }

  /** Whether `dn` is a member of the group, directly or through groups that are members (Active Directory's chain rule). */
  private inChain(group: FakeEntry, dn: string, seen = new Set<string>()): boolean {
    const key = normalizeDn(group.dn) ?? group.dn;
    if (seen.has(key)) return false;
    seen.add(key);
    for (const value of this.values(group, "member")) {
      const member = lower(value);
      if (normalizeDn(member) === normalizeDn(dn)) return true;
      const nested = this.byDn(member);
      if (nested && this.inChain(nested, dn, seen)) return true;
    }
    return false;
  }

  matches(filter: Filter, entry: FakeEntry): boolean {
    if (filter instanceof AndFilter) return filter.filters.every((f) => this.matches(f, entry));
    if (filter instanceof OrFilter) return filter.filters.some((f) => this.matches(f, entry));
    if (filter instanceof NotFilter) return !this.matches(filter.filter, entry);
    if (filter instanceof PresenceFilter) return this.values(entry, filter.attribute).length > 0;
    if (filter instanceof EqualityFilter) {
      const wanted = Buffer.isBuffer(filter.value) ? filter.value.toString("hex") : filter.value;
      return this.values(entry, filter.attribute).some((v) => {
        if (Buffer.isBuffer(v) && !Buffer.isBuffer(filter.value)) return false;
        const have = Buffer.isBuffer(v) ? v.toString("hex") : v;
        // Names compare as names; everything else as case-insensitive text.
        if (parseDn(have) && parseDn(wanted) && have.includes("=") && wanted.includes("=")) {
          return normalizeDn(have) === normalizeDn(wanted);
        }
        return have.toLowerCase() === wanted.toLowerCase();
      });
    }
    if (filter instanceof SubstringFilter) {
      return this.values(entry, filter.attribute).some((v) => {
        const text = lower(v);
        let at = 0;
        if (filter.initial) {
          if (!text.startsWith(filter.initial.toLowerCase())) return false;
          at = filter.initial.length;
        }
        for (const part of filter.any) {
          const found = text.indexOf(part.toLowerCase(), at);
          if (found === -1) return false;
          at = found + part.length;
        }
        return !filter.final || text.slice(at).endsWith(filter.final.toLowerCase());
      });
    }
    if (filter instanceof ExtensibleFilter) {
      if (filter.rule === CHAIN_RULE && filter.matchType.toLowerCase() === "member")
        return this.inChain(entry, filter.value);
      return false;
    }
    return false;
  }
}

function inScope(dn: string, request: SearchRequest): boolean {
  const same = normalizeDn(dn) === normalizeDn(request.baseDN);
  if (request.scope === "base") return same;
  if (request.scope === "one") {
    const child = parseDn(dn);
    const base = parseDn(request.baseDN);
    return !!child && !!base && child.length === base.length + 1 && isUnderDn(dn, request.baseDN);
  }
  return isUnderDn(dn, request.baseDN);
}
