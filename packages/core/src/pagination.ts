/**
 * Cursor (keyset) pagination shared by API and web.
 *
 * Lists are ordered by one sort key plus the row ID as a tie-breaker. A cursor
 * encodes the sort value and ID of the last row of a page, so new rows never
 * shift later pages and deep pages stay fast. Cursors are opaque to clients;
 * a malformed cursor is rejected instead of being guessed at.
 */
import { z } from "zod";

export const PAGE_SIZES = [25, 50, 100] as const;
export type PageSize = (typeof PAGE_SIZES)[number];
export const DEFAULT_PAGE_SIZE: PageSize = 25;

export const pageSizeSchema = z.coerce
  .number()
  .int()
  .refine((n): n is PageSize => (PAGE_SIZES as readonly number[]).includes(n), "Unsupported page size")
  .default(DEFAULT_PAGE_SIZE);

const cursorSchema = z.object({
  /** Sort value of the boundary row: string, number or ISO date. */
  k: z.union([z.string(), z.number()]),
  /** ID of the boundary row. */
  id: z.string().min(1),
  /** Direction: "a" = after (next page), "b" = before (previous page). */
  d: z.enum(["a", "b"]),
});

export type Cursor = z.infer<typeof cursorSchema>;

// Universal base64url (works in Node and browsers, no Buffer).
function toBase64Url(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(value: string): string {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new InvalidCursorError();
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
}

export function encodeCursor(cursor: Cursor): string {
  return toBase64Url(JSON.stringify(cursor));
}

export function decodeCursor(value: string | undefined | null): Cursor | null {
  if (!value) return null;
  if (value.length > 512) throw new InvalidCursorError();
  try {
    return cursorSchema.parse(JSON.parse(fromBase64Url(value)));
  } catch {
    throw new InvalidCursorError();
  }
}

export class InvalidCursorError extends Error {
  constructor() {
    super("Invalid cursor");
    this.name = "InvalidCursorError";
  }
}

/** The envelope every paginated endpoint returns. */
export interface Page<T> {
  items: T[];
  /** Total rows matching the filter (not just this page). */
  total: number;
  pageSize: number;
  /** Cursor for the next page, or null on the last page. */
  next: string | null;
  /** Cursor for the previous page, or null on the first page. */
  prev: string | null;
}
