/**
 * For the end-to-end tests of the web app only (apps/web/e2e): the directory part of the worker
 * (ADR 0020) plus a fake Active Directory (LDAPS, throw-away certificates made with openssl) in
 * one process, and a small control server on plain http for the tests to change group
 * memberships and certificates, run the periodic check, and look at what the directory saw. The
 * real worker stays off there: it would also pick up the scans other tests queue.
 *
 * The server address the tests enter names a host name under example.lan; the hook below opens
 * the socket to this process on loopback instead, while the address policy still judges the
 * configured name. Run with: tsx test/e2e-directory-worker.ts (environment as for the worker).
 */
import { execFileSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PgBoss } from "pg-boss";
import { DIRECTORY_QUEUE, reconcileAll, runDirectoryRequest } from "../src/directory.ts";
import { env } from "../src/env.ts";
import { AD, activeDirectory } from "./directory-fixtures.ts";
import { FakeLdapServer } from "./fake-ldap.ts";

const ldapPort = Number(process.env.E2E_DIRECTORY_PORT ?? 8096);
const controlPort = Number(process.env.E2E_DIRECTORY_CONTROL_PORT ?? 8095);
const HOST = "dc1.example.lan";

function certificate(dir: string, name: string): { key: string; cert: string } {
  const keyFile = join(dir, `${name}.key`);
  const certFile = join(dir, `${name}.pem`);
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:prime256v1",
      "-nodes",
      "-days",
      "2",
      "-subj",
      `/CN=${HOST}/O=Example ${name}`,
      "-addext",
      `subjectAltName=DNS:${HOST}`,
      "-keyout",
      keyFile,
      "-out",
      certFile,
    ],
    { stdio: "ignore" },
  );
  return { key: readFileSync(keyFile, "utf8"), cert: readFileSync(certFile, "utf8") };
}

const dir = mkdtempSync(join(tmpdir(), "garnetops-e2e-directory-"));
const certs = { A: certificate(dir, "A"), B: certificate(dir, "B") };
const fingerprint = (cert: string) => new X509Certificate(cert).fingerprint256;

const data = activeDirectory();
const fixed = new FakeLdapServer({ ...data, mode: "ldaps", tls: certs.A, requireTls: true, port: ldapPort });
await fixed.start();
const net = { resolve: async () => "127.0.0.1" };

const GROUPS = { admins: AD.admins, users: AD.users, viewers: AD.viewers } as const;
const USERS: Record<string, string> = {
  jdoe: AD.user("John Doe"),
  asmith: AD.user("Anna Smith"),
  bwilson: AD.user("Ben Wilson"),
  cnoone: AD.user("Cleo Noone"),
  lperson: AD.user("Local Person"),
};

/** Puts a person into exactly these groups (any of admins, users, viewers). */
function setGroups(user: string, groups: (keyof typeof GROUPS)[]): void {
  const dn = USERS[user];
  if (!dn) throw new Error("unknown user");
  for (const entry of fixed.entries) {
    if (Object.values(GROUPS).includes(entry.dn as never)) {
      const members = (entry.attributes.member as string[]).filter((m) => m !== dn);
      if (groups.some((g) => GROUPS[g] === entry.dn)) members.push(dn);
      entry.attributes.member = members;
    }
    if (entry.dn === dn) entry.attributes.memberOf = groups.map((g) => GROUPS[g]);
  }
}

createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://x");
  res.setHeader("content-type", "application/json");
  let body = "";
  req.on("data", (c) => {
    body += c;
  });
  req.on("end", () => {
    void (async () => {
      try {
        if (url.pathname === "/state") {
          return void res.end(
            JSON.stringify({
              url: `ldaps://${HOST}:${ldapPort}`,
              ca: certs.A.cert,
              fingerprintA: fingerprint(certs.A.cert),
              fingerprintB: fingerprint(certs.B.cert),
              seen: fixed.seen.filter((s) => s.op !== "unbind"),
            }),
          );
        }
        if (url.pathname === "/groups" && req.method === "POST") {
          const input = JSON.parse(body) as { user: string; groups: (keyof typeof GROUPS)[] };
          setGroups(input.user, input.groups);
          return void res.end("{}");
        }
        if (url.pathname === "/certificate" && req.method === "POST") {
          const input = JSON.parse(body) as { which: "A" | "B" };
          fixed.setCertificate(certs[input.which]);
          return void res.end("{}");
        }
        if (url.pathname === "/reconcile" && req.method === "POST") {
          await reconcileAll({ net });
          return void res.end("{}");
        }
        if (url.pathname === "/reset") {
          fixed.seen.length = 0;
          return void res.end("{}");
        }
        res.writeHead(404).end("{}");
      } catch (error) {
        res.writeHead(500).end(JSON.stringify({ error: (error as Error).message }));
      }
    })();
  });
}).listen(controlPort, "127.0.0.1", () =>
  console.log(`e2e: fake directory on 127.0.0.1:${ldapPort}, control on 127.0.0.1:${controlPort}`),
);

const boss = new PgBoss({ connectionString: env.DATABASE_URL, application_name: "garnetops-e2e-directory" });
boss.on("error", (error) => console.error("queue:", error.message));
await boss.start();
await boss.createQueue(DIRECTORY_QUEUE);
await boss.work<{ requestId: string }>(
  DIRECTORY_QUEUE,
  { batchSize: 1, pollingIntervalSeconds: 0.5 },
  async ([job]) => {
    if (job) await runDirectoryRequest(job.data.requestId, { net });
  },
);
