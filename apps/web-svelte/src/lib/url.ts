import type { z } from "zod";

/** A value in the address: dropped when undefined, null or empty. */
export type SearchValue = string | number | boolean | undefined | null;
export type SearchParams = Record<string, SearchValue>;

/**
 * An app path with plain search parameters (`/findings?severity=critical&kev=1`), keys in the order given. Plain values
 * instead of JSON keep shared links readable; the zod schemas in search.ts parse and coerce every value.
 */
export function href(path: string, search: SearchParams = {}): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(search)) {
    if (value === undefined || value === null || value === "") continue;
    params.append(key, String(value));
  }
  const query = params.toString();
  return query ? `${path}?${query}` : path;
}

/** The search parameters of `url` through `schema`; invalid values fall back to the schema's defaults. */
export function parseSearch<S extends z.ZodTypeAny>(schema: S, url: URL | { searchParams: URLSearchParams }): z.infer<S> {
  return schema.parse(Object.fromEntries(url.searchParams));
}
