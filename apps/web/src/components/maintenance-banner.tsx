import { formatMessage, interpolate, messagesFor } from "@restow-backup/cicd-updater/messages";
import { formatCountdown, useMaintenance } from "@restow-backup/cicd-updater/react";
import { CircleCheck, CircleX, Clock, LoaderCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { cn } from "../lib/cn.ts";
import { fetchMaintenance, fetchPublicStatus, maintenanceChanged } from "../lib/updates.ts";

/**
 * The update banner every signed-in user sees (ADR 0007): a countdown while an update
 * is scheduled, progress while it runs, the result when it ended. Nothing while idle or
 * when the installation has no update sidecar. After a successful update the page
 * reloads once, so everyone gets the new web app.
 *
 * Texts of phases, steps and results come from the cicd-updater catalogs (English,
 * German) in the UI language. Only the phase line is a live region; the ticking
 * countdown sits outside it, so screen readers do not announce every second.
 */
export function MaintenanceBanner() {
  // A fresh poller after an action in this browser, so the banner follows at once.
  const [generation, setGeneration] = useState(0);
  useEffect(() => {
    const bump = () => setGeneration((g) => g + 1);
    maintenanceChanged.addEventListener("change", bump);
    return () => maintenanceChanged.removeEventListener("change", bump);
  }, []);
  return <Banner key={generation} />;
}

function Banner() {
  const { i18n } = useTranslation();
  const snapshot = useMaintenance({ fetchMaintenance, fetchPublicStatus });
  const view = snapshot.view;
  if (!view || snapshot.phase === "idle") return null;

  const messages = messagesFor(i18n.language);
  const { phase } = snapshot;
  const failed = phase === "failed" || (view.outcome !== null && view.outcome !== "succeeded");
  const succeeded = phase === "succeeded" && view.outcome === "succeeded";
  const Icon =
    phase === "scheduled" ? Clock : phase === "running" ? LoaderCircle : failed ? CircleX : CircleCheck;
  const title =
    phase === "scheduled"
      ? messages.ui.updateScheduled
      : phase === "running"
        ? messages.ui.updateRunning
        : failed
          ? messages.ui.updateFailed
          : messages.ui.updateSucceeded;
  const detail = view.outcome ? messages.outcomes[view.outcome] : formatMessage(messages, view.message);

  return (
    <div
      data-state={phase}
      className={cn(
        "mb-5 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border bg-card px-4 py-3 shadow-xs",
        // Green means proof: only a finished, healthy update is shown as success (AGENTS.md rule 6).
        succeeded ? "border-success/50" : failed ? "border-destructive/50" : "border-info/40",
      )}
    >
      <Icon
        aria-hidden="true"
        className={cn(
          "size-5 flex-none",
          succeeded ? "text-success-text" : failed ? "text-destructive-text" : "text-info-text",
          phase === "running" && "motion-safe:animate-spin",
        )}
      />
      <div role="status" className="min-w-0 flex-[1_1_18rem]">
        <span className="font-semibold">{title}</span> <span className="text-muted-foreground">{detail}</span>
        {succeeded ? <span className="text-muted-foreground"> {messages.ui.reloadHint}</span> : null}
      </div>
      {phase === "scheduled" ? (
        <span className="font-mono tabular-nums">
          {snapshot.countdownSeconds && snapshot.countdownSeconds > 0
            ? interpolate(messages.ui.startsIn, { time: formatCountdown(snapshot.countdownSeconds) })
            : messages.ui.startingNow}
        </span>
      ) : null}
      {phase === "running" ? (
        <div className="flex w-full items-center gap-3 @xl:w-72">
          <progress
            max={100}
            value={view.progress}
            aria-label={interpolate(messages.ui.progress, { progress: view.progress })}
            className="h-2 flex-1 overflow-hidden rounded-full bg-muted [&::-moz-progress-bar]:bg-info [&::-webkit-progress-bar]:bg-muted [&::-webkit-progress-value]:bg-info"
          />
          <span className="text-sm whitespace-nowrap tabular-nums">
            {interpolate(messages.ui.progress, { progress: view.progress })}
          </span>
        </div>
      ) : null}
    </div>
  );
}
