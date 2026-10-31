/**
 * Who sees which repository (ADR 0030): every member sees the repositories shared with the organisation, and each
 * person also sees their own private ones. Every read of repository data for a signed-in person goes through these
 * conditions; there is no other way in.
 */
import { type AnyColumn, type SQL, sql } from "drizzle-orm";
import { repository } from "./schema.ts";

export interface Viewer {
  organizationId: string;
  userId: string;
}

/** The ids of the repositories a person sees, as a subquery. */
export const visibleRepositoryIds = (viewer: Viewer): SQL =>
  sql`select ${repository.id} from ${repository} where ${repository.organizationId} = ${viewer.organizationId} and (${repository.visibility} = 'organization' or ${repository.ownerUserId} = ${viewer.userId})`;

/** A row whose repository the person sees. */
export const visibleRepository = (column: AnyColumn | SQL, viewer: Viewer): SQL =>
  sql`${column} in (${visibleRepositoryIds(viewer)})`;

/** On the repository table itself. */
export const repositoryVisibleTo = (viewer: Viewer): SQL =>
  sql`(${repository.organizationId} = ${viewer.organizationId} and (${repository.visibility} = 'organization' or ${repository.ownerUserId} = ${viewer.userId}))`;

/**
 * A row whose repository is active (ADR 0043). Views over the whole organisation (overview, findings, packages, statistics,
 * early warnings, pull requests) leave inactive repositories out; anything about one repository still shows it.
 */
export const activeRepository = (column: AnyColumn | SQL): SQL =>
  sql`${column} in (select ${repository.id} from ${repository} where ${repository.inactiveAt} is null)`;
