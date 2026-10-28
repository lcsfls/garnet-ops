import { type AdminMessages, describeCode, type Messages } from "@restow-backup/cicd-updater/messages";
import { ApiError } from "../../../api.ts";

/** Manual update steps and the recovery runbook (docs/updating.md). */
export const UPDATING_DOCS = "https://github.com/lcsfls/garnet-ops/blob/main/docs/updating.md";
export const RUNBOOK_DOCS = `${UPDATING_DOCS}#an-update-needs-attention`;

/**
 * Without the update service an installation builds the newest release tag from the repository. The version comes from
 * the tag, so the commands never go stale.
 */
export const SOURCE_UPDATE = [
  "docker compose exec db pg_dump -U garnetops -Fc garnetops > garnetops-$(date +%F).dump",
  "git fetch --tags",
  "TAG=$(git tag --list 'v*' --sort=-v:refname | head -n 1)",
  'git checkout "$TAG"',
  'VERSION=$(echo "$TAG" | cut -c2-)',
  'docker build --target app -t garnetops:local --build-arg VERSION="$VERSION" .',
  'docker build --target web -t garnetops-web:local --build-arg VERSION="$VERSION" .',
  "docker compose up -d",
].join("\n");

/** One sentence for an error answer; sidecar codes go through the cicd-updater catalogs. */
export function explain(error: unknown, messages: Messages, texts: AdminMessages): string {
  if (!(error instanceof ApiError)) return texts.offline;
  const problem = (error.problem ?? {}) as {
    blockers?: { code: string }[];
    reasons?: string[];
    feedError?: string;
  };
  switch (error.code) {
    case "forbidden":
    case "unauthenticated":
      return texts.forbidden;
    case "step-up-required":
      return texts.stepUp;
    case "updater_unavailable":
      return texts.noSidecar;
    case "blocked":
      return [
        describeCode(messages, "problems", "blocked"),
        ...(problem.blockers ?? []).map((b) => describeCode(messages, "blockers", b.code)),
      ].join(" ");
    case "release_refused":
      return [
        describeCode(messages, "problems", "release_refused"),
        ...(problem.reasons ?? []).map((r) => describeCode(messages, "refusals", r)),
      ].join(" ");
    case "feed_unavailable":
      return [
        describeCode(messages, "problems", "feed_unavailable"),
        problem.feedError ? describeCode(messages, "feedErrors", problem.feedError) : "",
      ].join(" ");
    default:
      return error.code ? describeCode(messages, "problems", error.code) : texts.offline;
  }
}
