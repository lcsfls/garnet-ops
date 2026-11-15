/**
 * Reading what package registries said (ADR 0051), shared by the API (lists, the repository's card) and the worker (the gate rule).
 * The answer for a package depends on the organisation: the public registries' answers are shared, an own registry's are the
 * organisation's.
 */
import { DEPRECATION_ECOSYSTEMS, type DeprecationEcosystem } from "@garnetops/core/deprecated";
import { type AnyColumn, and, eq, inArray, type SQL, sql } from "drizzle-orm";
import type { Database } from "./index.ts";
import * as schema from "./schema.ts";

type Reader = Pick<Database, "select">;

export interface DeprecationView {
  enabled: boolean;
  /** Where each ecosystem's answers are kept: "public" or the organisation's id. */
  scopes: Record<DeprecationEcosystem, string>;
}

export async function deprecationView(db: Reader, organizationId: string): Promise<DeprecationView> {
  const [row] = await db
    .select({
      enabled: schema.deprecationSettings.enabled,
      registries: schema.deprecationSettings.registries,
    })
    .from(schema.deprecationSettings)
    .where(eq(schema.deprecationSettings.organizationId, organizationId))
    .limit(1);
  const scopes = Object.fromEntries(
    DEPRECATION_ECOSYSTEMS.map((e) => [e, row?.registries?.[e] ? organizationId : "public"]),
  ) as Record<DeprecationEcosystem, string>;
  return { enabled: row?.enabled === true, scopes };
}

/** A package type's ecosystem in SQL (null for types the module does not cover). */
const ecosystemSql = (type: AnyColumn | SQL) =>
  sql`(case ${type} when 'npm' then 'npm' when 'python' then 'pypi' when 'rust-crate' then 'crates' end)`;
const scopeSql = (type: AnyColumn | SQL, view: DeprecationView) =>
  sql`(case ${type} when 'npm' then ${view.scopes.npm} when 'python' then ${view.scopes.pypi} when 'rust-crate' then ${view.scopes.crates} end)`;

/** The `package_status` row of a package as a condition, for `exists (...)` and correlated subqueries. */
export function packageStatusMatch(
  view: DeprecationView,
  pkg: { type: AnyColumn | SQL; name: AnyColumn | SQL; version: AnyColumn | SQL },
): SQL {
  const s = schema.packageStatus;
  return sql`${s.scope} = ${scopeSql(pkg.type, view)} and ${s.ecosystem} = ${ecosystemSql(pkg.type)}
    and ${s.name} = ${pkg.name} and ${s.version} = ${pkg.version}`;
}

/** Whether the package is known to be deprecated or yanked (false while the module is off). */
export function deprecatedSql(
  view: DeprecationView,
  pkg: { type: AnyColumn | SQL; name: AnyColumn | SQL; version: AnyColumn | SQL },
): SQL {
  if (!view.enabled) return sql`false`;
  const s = schema.packageStatus;
  return sql`exists (select 1 from ${s} where ${packageStatusMatch(view, pkg)} and ${s.state} in ('deprecated', 'yanked'))`;
}

/** What the registry said of each of these packages, by `type\0name\0version`; only deprecated and yanked ones. */
export async function deprecatedPackages(
  db: Reader,
  organizationId: string,
  packages: { type: string; name: string; version: string }[],
): Promise<Map<string, { state: "deprecated" | "yanked"; message: string | null }>> {
  const out = new Map<string, { state: "deprecated" | "yanked"; message: string | null }>();
  const view = await deprecationView(db, organizationId);
  if (!view.enabled || packages.length === 0) return out;
  const typeOf: Record<DeprecationEcosystem, string> = { npm: "npm", pypi: "python", crates: "rust-crate" };
  const s = schema.packageStatus;
  const names = [...new Set(packages.map((p) => p.name))];
  for (let i = 0; i < names.length; i += 1000) {
    const rows = await db
      .select({
        scope: s.scope,
        ecosystem: s.ecosystem,
        name: s.name,
        version: s.version,
        state: s.state,
        message: s.message,
      })
      .from(s)
      .where(and(inArray(s.name, names.slice(i, i + 1000)), inArray(s.state, ["deprecated", "yanked"])));
    for (const r of rows) {
      if (view.scopes[r.ecosystem] !== r.scope) continue;
      out.set(`${typeOf[r.ecosystem]}\u0000${r.name}\u0000${r.version}`, {
        state: r.state as "deprecated" | "yanked",
        message: r.message,
      });
    }
  }
  const wanted = new Set(packages.map((p) => `${p.type}\u0000${p.name}\u0000${p.version}`));
  for (const key of out.keys()) if (!wanted.has(key)) out.delete(key);
  return out;
}
