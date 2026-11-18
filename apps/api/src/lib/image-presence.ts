/**
 * Whether the package of a repository finding is in a running image built from that repository (ADR 0054): the link is the
 * image's source label against the repository's address, the evidence is the package list the agent read from the image. Read
 * at request time, stored nowhere, and it changes no finding, grade or gate.
 */
import { sourceKey } from "@garnetops/core/agent";
import {
  type ImageFilter,
  type ImagePresence,
  imagePresence,
  type PresenceCaveat,
  type PresenceUnknown,
  presenceCaveatOf,
  presenceName,
} from "@garnetops/core/image-presence";
import { schema } from "@garnetops/db";
import { and, asc, eq, inArray, isNotNull, type SQL, sql } from "drizzle-orm";
import { db } from "../db.ts";
import { modulesOf } from "./modules.ts";

const f = schema.finding;
const h = schema.agentHost;
const hc = schema.hostContainer;
const ci = schema.containerImage;
/** The package list of an image as rows; what an agent sent is never trusted to be a list. */
const isList = sql`jsonb_typeof(${ci.packages}) = 'array'`;
const packagesOf = sql`jsonb_array_elements(case when ${isList} then ${ci.packages} else '[]'::jsonb end)`;

/** What is known about the running images of an organisation's repositories. */
export interface PresenceScope {
  organizationId: string;
  hostsOn: boolean;
  /** Per repository with at least one running image built from it: the link key, the images and how many were read. */
  repositories: Map<string, { key: string; images: number; read: number }>;
}

export async function presenceScope(organizationId: string): Promise<PresenceScope> {
  const scope: PresenceScope = { organizationId, hostsOn: false, repositories: new Map() };
  scope.hostsOn = (await modulesOf(organizationId)).hosts;
  if (!scope.hostsOn) return scope;
  const images = await db
    .select({
      key: ci.sourceKey,
      images: sql<number>`count(distinct ${ci.imageId})::int`,
      read: sql<number>`count(distinct ${ci.imageId}) filter (where ${isList})::int`,
    })
    .from(hc)
    .innerJoin(ci, and(eq(ci.organizationId, hc.organizationId), eq(ci.imageId, hc.imageId)))
    .where(and(eq(hc.organizationId, organizationId), isNotNull(ci.sourceKey)))
    .groupBy(ci.sourceKey);
  if (images.length === 0) return scope;
  const byKey = new Map(images.map((row) => [row.key as string, row]));
  const repositories = await db
    .select({ id: schema.repository.id, url: schema.repository.url })
    .from(schema.repository)
    .where(eq(schema.repository.organizationId, organizationId));
  for (const repository of repositories) {
    const key = sourceKey(repository.url);
    const row = key ? byKey.get(key) : undefined;
    if (key && row) scope.repositories.set(repository.id, { key, images: row.images, read: row.read });
  }
  return scope;
}

/** The repositories whose findings have an answer: at least one of their running images was read. */
const answerable = (scope: PresenceScope) => [...scope.repositories].filter(([, r]) => r.read > 0);

/**
 * The findings whose package is (`in`) or is not (`not-in`) in a running image of their repository. Findings without an answer
 * are in neither. One pass over the images' package lists, joined by key, name and type.
 */
export function presenceCondition(scope: PresenceScope, want: ImageFilter): SQL {
  const repositories = answerable(scope);
  if (repositories.length === 0) return sql`false`;
  const keyOfRepository = sql`case ${f.repositoryId} ${sql.join(
    repositories.map(([id, r]) => sql`when ${id} then ${r.key}`),
    sql` `,
  )} end`;
  const keys = [...new Set(repositories.map(([, r]) => r.key))];
  const shipped = sql`(select distinct ${ci.sourceKey} as key, lower(pkg->>'name') as name, pkg->>'type' as type
    from ${hc} join ${ci} on ${ci.organizationId} = ${hc.organizationId} and ${ci.imageId} = ${hc.imageId}
      cross join lateral ${packagesOf} pkg
    where ${hc.organizationId} = ${scope.organizationId} and ${inArray(ci.sourceKey, keys)})`;
  const found = sql`exists (select 1 from ${shipped} shipped where shipped.key = ${keyOfRepository}
    and shipped.name = lower(${f.packageName}) and shipped.type = ${f.packageType})`;
  const inScope = inArray(
    f.repositoryId,
    repositories.map(([id]) => id),
  );
  return want === "in" ? sql`(${inScope} and ${found})` : sql`(${inScope} and not ${found})`;
}

type Package = { repositoryId: string; packageName: string; packageType: string };

/** The answer for each row of a page of findings, in one query. */
export async function presenceOf(scope: PresenceScope, rows: Package[]): Promise<(ImagePresence | null)[]> {
  const wanted = rows.flatMap((row) => {
    const repository = scope.repositories.get(row.repositoryId);
    return repository && repository.read > 0
      ? [{ key: repository.key, name: presenceName(row.packageName) }]
      : [];
  });
  const found = new Set<string>();
  if (wanted.length > 0) {
    const keys = [...new Set(wanted.map((w) => w.key))];
    const names = [...new Set(wanted.map((w) => w.name))];
    const hits = await db.execute<{ key: string; name: string; type: string }>(
      sql`select distinct ${ci.sourceKey} as key, lower(pkg->>'name') as name, pkg->>'type' as type
        from ${hc} join ${ci} on ${ci.organizationId} = ${hc.organizationId} and ${ci.imageId} = ${hc.imageId}
          cross join lateral ${packagesOf} pkg
        where ${hc.organizationId} = ${scope.organizationId} and ${inArray(ci.sourceKey, keys)}
          and ${inArray(sql`lower(pkg->>'name')`, names)}`,
    );
    for (const hit of hits.rows) found.add(`${hit.key}\u0000${hit.name}\u0000${hit.type}`);
  }
  return rows.map((row) => {
    const repository = scope.repositories.get(row.repositoryId);
    return imagePresence({
      hostsOn: scope.hostsOn,
      images: repository?.images ?? 0,
      read: repository?.read ?? 0,
      found: repository
        ? found.has(`${repository.key}\u0000${presenceName(row.packageName)}\u0000${row.packageType}`)
        : false,
    }).state;
  });
}

export interface PresenceDetail {
  state: ImagePresence | null;
  reason: PresenceUnknown | null;
  /** What "not found" cannot rule out for this kind of package. */
  caveat: PresenceCaveat | null;
  /** The running containers built from the repository: the version of the package in each, null when it is not there. */
  containers: {
    hostId: string;
    hostName: string;
    name: string;
    imageRef: string;
    read: boolean;
    version: string | null;
  }[];
}

const MAX_CONTAINERS = 20;

/** Everything about one finding: the answer, and each running container it rests on. */
export async function presenceDetail(scope: PresenceScope, finding: Package): Promise<PresenceDetail> {
  const repository = scope.repositories.get(finding.repositoryId);
  const caveat = presenceCaveatOf(finding.packageType);
  if (!repository) {
    return {
      ...imagePresence({ hostsOn: scope.hostsOn, images: 0, read: 0, found: false }),
      caveat,
      containers: [],
    };
  }
  const version = sql<string | null>`(select left(coalesce(pkg->>'version', ''), 100)
    from ${packagesOf} pkg
    where lower(pkg->>'name') = ${presenceName(finding.packageName)} and pkg->>'type' = ${finding.packageType}
    limit 1)`;
  const containers = await db
    .select({
      hostId: hc.hostId,
      hostName: h.name,
      name: hc.name,
      imageRef: hc.imageRef,
      read: sql<boolean>`coalesce(${isList}, false)`,
      version,
    })
    .from(hc)
    .innerJoin(h, eq(h.id, hc.hostId))
    .innerJoin(ci, and(eq(ci.organizationId, hc.organizationId), eq(ci.imageId, hc.imageId)))
    .where(and(eq(hc.organizationId, scope.organizationId), eq(ci.sourceKey, repository.key)))
    // Where it is comes first, so a long list never cuts off the evidence.
    .orderBy(sql`${version} is null`, asc(h.name), asc(hc.name))
    .limit(MAX_CONTAINERS);
  return {
    ...imagePresence({
      hostsOn: scope.hostsOn,
      images: repository.images,
      read: repository.read,
      found: containers.some((c) => c.version !== null),
    }),
    caveat,
    containers,
  };
}
