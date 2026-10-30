import { newId } from "@garnetops/core";
import {
  enrolBodySchema,
  hashEnrolmentCode,
  hostPackagesSchema,
  inventorySchema,
  kernelPackage,
  NONCE_TTL_MS,
  packagesSchema,
  parseSignedHeader,
  SIGNATURE_WINDOW_MS,
  sourceKey,
  verifySignature,
} from "@garnetops/core/agent";
import { schema } from "@garnetops/db";
import { and, eq, gt, inArray, isNull, lt, notInArray, sql } from "drizzle-orm";
import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import type { ZodType } from "zod";
import { boss, db, QUEUES } from "../db.ts";
import { env } from "../env.ts";
import {
  AGENT_ARCHES,
  type AgentArch,
  agentBinary,
  agentBinaryName,
  installScript,
} from "../lib/agent-install.ts";
import { audit } from "../lib/audit.ts";
import { clientIp } from "../lib/ip.ts";
import { modulesOf } from "../lib/modules.ts";
import { ProblemError } from "../lib/problem.ts";
import { rateLimit } from "../lib/rate-limit.ts";

/**
 * The API the host agent talks to (ADR 0034). No cookies and no session: enrolment takes a one-time code, every other request is
 * signed with the host's Ed25519 key. Registered before the same-origin check and the session middleware. Everything a host sends
 * is hostile input; the schemas in @garnetops/core/agent clean and cut it.
 */

type AgentHost = typeof schema.agentHost.$inferSelect;
type AgentEnv = { Variables: { host: AgentHost; body: string } };

/** Requests per host and hour: an inventory and up to a few hundred package lists after a deploy. */
const HOST_RATE_LIMIT = 600;
/** At most this many image ids are asked for in one answer; the rest follow at the next report. */
export const PACKAGE_REQUESTS_PER_INVENTORY = 50;

const unauthorized = () =>
  new ProblemError(401, "invalid-agent-signature", "The request is not signed by a known host");
const moduleOff = () =>
  new ProblemError(409, "module-off", "This module is switched off", undefined, { module: "hosts" });

function parse<T>(schemaOf: ZodType<T>, text: string): T {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new ProblemError(400, "invalid-json", "The body is not JSON");
  }
  return schemaOf.parse(json);
}

/** Checks the signature, the time window and the nonce, then hands the host and the exact body to the route. */
const requireSignedHost = createMiddleware<AgentEnv>(async (c, next) => {
  const header = parseSignedHeader(c.req.header("authorization"));
  if (!header) throw unauthorized();
  const now = Date.now();
  if (Math.abs(now - header.timestamp) > SIGNATURE_WINDOW_MS) {
    throw new ProblemError(401, "clock-skew", "The request is too old or from the future");
  }
  const [host] = await db
    .select()
    .from(schema.agentHost)
    .where(eq(schema.agentHost.id, header.hostId))
    .limit(1);
  if (!host) throw unauthorized();
  const body = await c.req.text();
  const url = new URL(c.req.url);
  const ok = verifySignature({
    publicKey: host.publicKey,
    method: c.req.method,
    path: `${url.pathname}${url.search}`,
    timestamp: header.timestamp,
    nonce: header.nonce,
    body,
    signature: header.signature,
  });
  if (!ok) throw unauthorized();
  // A nonce counts once: a replayed request is refused even within the time window.
  const fresh = await db
    .insert(schema.agentNonce)
    .values({ hostId: host.id, nonce: header.nonce, seenAt: new Date(now) })
    .onConflictDoNothing()
    .returning({ nonce: schema.agentNonce.nonce });
  if (fresh.length === 0) throw new ProblemError(401, "replayed", "This request was already received");
  await db.delete(schema.agentNonce).where(lt(schema.agentNonce.seenAt, new Date(now - NONCE_TTL_MS)));
  if (!(await modulesOf(host.organizationId)).hosts) throw moduleOff();
  await rateLimit(`agent:${host.id}`, HOST_RATE_LIMIT, 3600_000);
  await db
    .update(schema.agentHost)
    .set({ lastSeenAt: new Date(now) })
    .where(eq(schema.agentHost.id, host.id));
  c.set("host", host);
  c.set("body", body);
  await next();
});

export const agentRoutes = new Hono<AgentEnv>()
  /** A host enrols once with the code an admin created, and its public key. The code is spent. */
  .post("/enrol", async (c) => {
    const ip = clientIp(c.req.raw.headers);
    await rateLimit(`agent-enrol:${ip ?? "unknown"}`, 20, 3600_000);
    const input = parse(enrolBodySchema, await c.req.text());
    const now = new Date();
    const e = schema.agentEnrolment;
    const result = await db.transaction(async (tx) => {
      // Spend the code first, under its unique hash, so two hosts cannot use it at the same time.
      const [code] = await tx
        .update(e)
        .set({ usedAt: now })
        .where(and(eq(e.codeHash, hashEnrolmentCode(input.code)), isNull(e.usedAt), gt(e.expiresAt, now)))
        .returning();
      if (!code) return null;
      if (!(await modulesOf(code.organizationId)).hosts) throw moduleOff();
      const id = newId("hst");
      await tx.insert(schema.agentHost).values({
        id,
        organizationId: code.organizationId,
        name: code.label || input.hostname || "host",
        hostname: input.hostname || "host",
        publicKey: input.publicKey,
        agentVersion: input.agentVersion,
        enrolledBy: code.createdBy,
        enrolledAt: now,
        lastSeenAt: now,
      });
      await tx.update(e).set({ hostId: id }).where(eq(e.id, code.id));
      return { id, organizationId: code.organizationId, enrolledBy: code.createdBy };
    });
    if (!result) throw new ProblemError(401, "invalid-enrolment-code", "The enrolment code is not valid");
    await audit(
      { organizationId: result.organizationId, userId: null, ip },
      "host.enrolled",
      { type: "host", id: result.id },
      { hostname: input.hostname, agentVersion: input.agentVersion, codeCreatedBy: result.enrolledBy },
    );
    return c.json({ hostId: result.id }, 201);
  })
  /** The install script of the systemd agent (ADR 0037), with this installation's address and the checksums of its binaries. */
  .get("/install.sh", async (c) => {
    await rateLimit(`agent-download:${clientIp(c.req.raw.headers) ?? "unknown"}`, 60, 3600_000);
    const sums: Partial<Record<AgentArch, string>> = {};
    for (const arch of AGENT_ARCHES) {
      const binary = await agentBinary(env.AGENT_BINARIES_DIR, arch);
      if (binary) sums[arch] = binary.sha256;
    }
    return c.body(installScript(env.PUBLIC_URL, sums), 200, {
      "content-type": "text/x-shellscript; charset=utf-8",
      "content-disposition": 'attachment; filename="garnetops-agent-install.sh"',
      "cache-control": "no-store",
    });
  })
  /** The binary of the systemd agent for one architecture, as this installation was built with it. */
  .get("/download/:target", async (c) => {
    await rateLimit(`agent-download:${clientIp(c.req.raw.headers) ?? "unknown"}`, 60, 3600_000);
    const arch = AGENT_ARCHES.find((a) => c.req.param("target") === `linux-${a}`);
    const binary = arch ? await agentBinary(env.AGENT_BINARIES_DIR, arch) : null;
    if (!arch || !binary)
      throw new ProblemError(404, "no-agent-binary", "This installation has no agent for that target");
    return c.body(new Uint8Array(binary.bytes), 200, {
      "content-type": "application/octet-stream",
      "content-disposition": `attachment; filename="${agentBinaryName(arch)}"`,
      "x-content-sha256": binary.sha256,
      "cache-control": "no-store",
    });
  })
  .use("/inventory", requireSignedHost)
  .use("/packages", requireSignedHost)
  .use("/host-packages", requireSignedHost)
  /**
   * The running containers and their images. Containers of this host that are not in the list are gone. The answer names the
   * images whose packages are still needed.
   */
  .post("/inventory", async (c) => {
    const host = c.get("host");
    const input = parse(inventorySchema, c.get("body"));
    const now = new Date();
    const org = host.organizationId;
    const used = new Set(input.containers.map((x) => x.imageId));
    const images = input.images.filter((i) => used.has(i.id));
    // The running kernel as the distribution's package; a new kernel (an update and a reboot) is matched again.
    const kernel = input.kernel ? kernelPackage(input.kernel) : null;
    const kernelPurl = kernel?.ok ? kernel.purl : null;
    const kernelChanged = kernelPurl !== (host.kernelPackage?.purl ?? null);
    const need = await db.transaction(async (tx) => {
      await tx
        .update(schema.agentHost)
        .set({
          hostname: input.hostname || host.hostname,
          agentVersion: input.agentVersion,
          dockerVersion: input.dockerVersion,
          os: input.kernel?.osName ?? input.os,
          lastInventoryAt: now,
          ...(input.runtime ? { runtime: input.runtime } : {}),
          ...(input.kernel
            ? {
                kernelRelease: input.kernel.release,
                osName: input.kernel.osName,
                kernelPackage: kernel?.ok
                  ? {
                      purl: kernel.purl,
                      name: kernel.name,
                      version: kernel.version,
                      type: kernel.type,
                      distro: kernel.distro,
                    }
                  : null,
                kernelProblem: kernel && !kernel.ok ? kernel.reason : null,
                ...(kernelChanged
                  ? { kernelMatchedAt: null, kernelMatchedDbBuilt: null, kernelMatchError: null }
                  : {}),
              }
            : {}),
        })
        .where(eq(schema.agentHost.id, host.id));
      if (input.kernel && kernelChanged) {
        await tx.delete(schema.hostKernelFinding).where(eq(schema.hostKernelFinding.hostId, host.id));
      }
      for (const image of images) {
        const values = {
          tags: image.tags,
          digests: image.digests,
          os: image.os,
          architecture: image.architecture,
          builtAt: image.created ? new Date(image.created) : null,
          labels: image.labels,
          sourceKey: sourceKey(image.labels["org.opencontainers.image.source"]),
          lastSeenAt: now,
        };
        await tx
          .insert(schema.containerImage)
          .values({ organizationId: org, imageId: image.id, firstSeenAt: now, ...values })
          .onConflictDoUpdate({
            target: [schema.containerImage.organizationId, schema.containerImage.imageId],
            set: values,
          });
      }
      const c2 = schema.hostContainer;
      const ids = input.containers.map((x) => x.id);
      await tx
        .delete(c2)
        .where(and(eq(c2.hostId, host.id), ids.length ? notInArray(c2.containerId, ids) : undefined));
      for (const container of input.containers) {
        const values = {
          name: container.name.replace(/^\//, ""),
          imageRef: container.image,
          imageId: container.imageId,
          state: container.state,
          startedAt: container.startedAt ? new Date(container.startedAt) : null,
          lastSeenAt: now,
        };
        await tx
          .insert(c2)
          .values({
            hostId: host.id,
            containerId: container.id,
            organizationId: org,
            firstSeenAt: now,
            ...values,
          })
          .onConflictDoUpdate({ target: [c2.hostId, c2.containerId], set: values });
      }
      if (used.size === 0) return [];
      // Images that some container uses but whose packages nobody has sent yet (another host may have).
      const missing = await tx
        .select({ imageId: schema.containerImage.imageId })
        .from(schema.containerImage)
        .where(
          and(
            eq(schema.containerImage.organizationId, org),
            inArray(schema.containerImage.imageId, [...used]),
            isNull(schema.containerImage.packagesAt),
          ),
        )
        .limit(PACKAGE_REQUESTS_PER_INVENTORY);
      return missing.map((m) => m.imageId);
    });
    if (kernelPurl && kernelChanged) {
      await boss.send(
        QUEUES.kernelMatch,
        { hostId: host.id },
        { retryLimit: 1, expireInSeconds: 1800, singletonKey: host.id },
      );
    }
    // The host's own packages (systemd agent) are sent again only when their list changed.
    const needHostPackages =
      input.hostPackagesDigest !== undefined && input.hostPackagesDigest !== host.hostPackagesDigest;
    return c.json({ needPackages: need, needHostPackages });
  })
  /** The packages installed on the host itself (systemd agent, ADR 0037): replace the list, then match it in the worker. */
  .post("/host-packages", async (c) => {
    const host = c.get("host");
    const input = parse(hostPackagesSchema, c.get("body"));
    const seen = new Set<string>();
    const packages = input.packages.filter((p) => !seen.has(p.purl) && seen.add(p.purl));
    await db
      .update(schema.agentHost)
      .set({
        hostPackages: packages,
        hostPackagesDigest: input.digest,
        hostPackagesDistro: input.distro,
        hostPackagesAt: new Date(),
        hostPackagesMatchedAt: null,
        hostPackagesMatchedDbBuilt: null,
        hostPackagesMatchError: null,
      })
      .where(eq(schema.agentHost.id, host.id));
    await boss.send(
      QUEUES.hostPackagesMatch,
      { hostId: host.id },
      { retryLimit: 1, expireInSeconds: 1800, singletonKey: host.id },
    );
    return c.json({ packages: packages.length }, 202);
  })
  /** The package list of one image this host runs. Matching happens in the worker. */
  .post("/packages", async (c) => {
    const host = c.get("host");
    const input = parse(packagesSchema, c.get("body"));
    const [runs] = await db
      .select({ n: sql<number>`count(*)::int` })
      .from(schema.hostContainer)
      .where(and(eq(schema.hostContainer.hostId, host.id), eq(schema.hostContainer.imageId, input.imageId)));
    if (!runs?.n) throw new ProblemError(404, "unknown-image", "No container of this host runs this image");
    // The same purl twice says nothing new.
    const seen = new Set<string>();
    const packages = input.packages.filter((p) => !seen.has(p.purl) && seen.add(p.purl));
    // An image id names its content, so its package list never changes: the first list stays, and one host cannot replace
    // the list of an image another host of the organisation runs.
    const stored = await db
      .update(schema.containerImage)
      .set({
        distro: input.distro,
        packages,
        packageCount: packages.length,
        packagesAt: new Date(),
        matchError: null,
      })
      .where(
        and(
          eq(schema.containerImage.organizationId, host.organizationId),
          eq(schema.containerImage.imageId, input.imageId),
          isNull(schema.containerImage.packagesAt),
        ),
      )
      .returning({ imageId: schema.containerImage.imageId });
    if (stored.length === 0)
      throw new ProblemError(409, "already-known", "The packages of this image are already known");
    await boss.send(
      QUEUES.imageMatch,
      { organizationId: host.organizationId, imageId: input.imageId },
      { retryLimit: 1, expireInSeconds: 1800, singletonKey: `${host.organizationId}:${input.imageId}` },
    );
    return c.json({ packages: packages.length }, 202);
  });
