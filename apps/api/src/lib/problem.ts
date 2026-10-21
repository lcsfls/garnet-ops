import type { Problem } from "@garnetops/core";
import { InvalidCursorError } from "@garnetops/core/pagination";
import type { Context } from "hono";
import { HTTPException } from "hono/http-exception";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { ZodError } from "zod";

/** Throw this from handlers; the error handler turns it into RFC 9457 problem details. */
export class ProblemError extends Error {
  readonly status: ContentfulStatusCode;
  readonly code: string;
  readonly title: string;
  readonly detail: string | undefined;
  /** RFC 9457 extension members, e.g. the blockers of a refused update. */
  readonly extensions: Record<string, unknown>;

  constructor(
    status: ContentfulStatusCode,
    code: string,
    title: string,
    detail?: string,
    extensions: Record<string, unknown> = {},
  ) {
    super(title);
    this.status = status;
    this.code = code;
    this.title = title;
    this.detail = detail;
    this.extensions = extensions;
  }
}

export const notFound = (what = "Resource") => new ProblemError(404, "not-found", `${what} not found`);
export const forbidden = (detail?: string) => new ProblemError(403, "forbidden", "Not allowed", detail);

function respond(c: Context, problem: Problem) {
  return c.body(JSON.stringify(problem), problem.status as ContentfulStatusCode, {
    "content-type": "application/problem+json",
  });
}

export function handleError(error: Error, c: Context) {
  if (error instanceof ProblemError) {
    return respond(c, {
      ...error.extensions,
      type: `https://garnetops.com/problems/${error.code}`,
      title: error.title,
      status: error.status,
      ...(error.detail ? { detail: error.detail } : {}),
    });
  }
  if (error instanceof ZodError) {
    return respond(c, {
      type: "https://garnetops.com/problems/validation",
      title: "The request is not valid",
      status: 422,
      errors: error.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
    });
  }
  if (error instanceof InvalidCursorError) {
    return respond(c, {
      type: "https://garnetops.com/problems/invalid-cursor",
      title: "Invalid page cursor",
      status: 400,
    });
  }
  if (error instanceof HTTPException) {
    return respond(c, {
      type: "about:blank",
      title: error.message || "Request failed",
      status: error.status,
    });
  }
  // Unexpected: log server-side with the stack, return nothing internal to the client.
  console.error(`[${c.req.method} ${c.req.path}]`, error);
  return respond(c, { type: "about:blank", title: "Internal error", status: 500 });
}
