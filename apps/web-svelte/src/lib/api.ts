import type { Problem } from "@garnetops/core";
import { sessionEnded } from "./session-end.ts";

/** An API error with the RFC 9457 problem details the server sent, if any. */
export class ApiError extends Error {
  readonly status: number;
  readonly problem: Problem | null;

  constructor(status: number, problem: Problem | null) {
    super(problem?.title ?? `HTTP ${status}`);
    this.status = status;
    this.problem = problem;
  }

  /** The last path segment of the problem type, e.g. "mfa-enrollment-required". */
  get code(): string | null {
    return this.problem?.type.split("/").pop() ?? null;
  }
}

/** Calls `/api/v1/...` with the session cookie. Throws ApiError on any non-2xx answer. */
export async function api<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    method: init.method ?? "GET",
    credentials: "same-origin",
    headers: {
      accept: "application/json",
      ...(init.body === undefined ? {} : { "content-type": "application/json" }),
    },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  if (!res.ok) {
    if (res.status === 401) sessionEnded();
    const isProblem = res.headers.get("content-type")?.includes("json");
    throw new ApiError(
      res.status,
      isProblem ? ((await res.json().catch(() => null)) as Problem | null) : null,
    );
  }
  if (res.status === 204) return undefined as T;
  // While the API is down for an update, the reverse proxy answers with its maintenance
  // page (HTML). That is "not reachable", not data.
  if (!res.headers.get("content-type")?.includes("json")) throw new ApiError(503, null);
  return (await res.json()) as T;
}
