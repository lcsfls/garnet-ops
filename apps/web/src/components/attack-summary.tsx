import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Sparkles } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import { formatRelative } from "../lib/format.ts";
import type { MessageKey } from "../lib/i18n.ts";
import type { AttackSummary } from "../lib/types.ts";
import { Markdown } from "./markdown.tsx";
import { Card, CardHeader } from "./page-header.tsx";
import { Alert } from "./ui/alert.tsx";
import { Badge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";

const camel = (code: string) => code.replace(/-(\w)/g, (_, c: string) => c.toUpperCase());

/**
 * "Summarise with AI" on the Attacks page (ADR 0016). The model sees counts per country code and
 * AS number only, never an address; its answer is untrusted text: labelled "AI suggestion" and
 * rendered by the safe Markdown renderer (no HTML, no images). Not shown at all while AI is not
 * configured and switched on.
 */
export function AttackSummaryCard({ canAsk, model }: { canAsk: boolean; model: string }) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);
  const summary = useQuery({
    queryKey: ["attacks-summary"],
    queryFn: () => api<{ summary: AttackSummary | null }>("/attacks/summary"),
    refetchInterval: (q) => {
      const s = q.state.data?.summary;
      return s && (s.status === "pending" || s.status === "running") ? 2000 : false;
    },
  });
  const ask = useMutation({
    mutationFn: () =>
      api("/attacks/summary", { method: "POST", body: { language: i18n.language === "de" ? "de" : "en" } }),
    onMutate: () => setError(null),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["attacks-summary"] }),
    onError: (e) => {
      if (e instanceof ApiError && e.code === "summary-busy")
        return setError(t("attacks.summaryAskError.busy"));
      if (e instanceof ApiError && e.code === "rate-limited")
        return setError(t("attacks.summaryAskError.rateLimited"));
      if (e instanceof ApiError && e.code === "ai-not-ready")
        return setError(t("attacks.summaryAskError.notReady"));
      if (e instanceof ApiError && e.code === "no-data") return setError(t("attacks.summaryAskError.noData"));
      setError(t("attacks.summaryAskError.generic"));
    },
  });
  const current = summary.data?.summary ?? null;
  const working = current?.status === "pending" || current?.status === "running";

  return (
    <Card>
      <CardHeader
        title={t("attacks.summaryTitle")}
        description={t("attacks.summaryDescription")}
        actions={
          canAsk ? (
            <Button
              variant="outline"
              className="h-9"
              disabled={working || ask.isPending}
              onClick={() => ask.mutate()}
            >
              <Sparkles aria-hidden="true" className="size-4" />
              {working ? t("attacks.summarising") : t("attacks.summarise")}
            </Button>
          ) : null
        }
      />
      <div className="grid gap-3 px-5 pb-5">
        {error ? <Alert tone="error">{error}</Alert> : null}
        {working ? (
          <p role="status" className="text-sm text-muted-foreground">
            {t("attacks.summarisePending")}
          </p>
        ) : null}
        {current?.status === "failed" ? (
          <Alert tone="error">
            {t("attacks.summaryFailed", {
              reason: t(`ai.error.${camel(current.error ?? "internal")}` as MessageKey),
            })}
          </Alert>
        ) : null}
        {current?.status === "complete" && current.content ? (
          <div className="grid gap-2" data-testid="attack-summary">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="info">
                <Sparkles aria-hidden="true" />
                {t("attacks.summaryLabel")}
              </Badge>
              <span className="text-sm text-muted-foreground">
                {current.author
                  ? t("attacks.summaryMeta", {
                      name: current.author,
                      when: formatRelative(current.createdAt),
                      model: current.model ?? model,
                    })
                  : t("attacks.summaryMetaNoName", {
                      when: formatRelative(current.createdAt),
                      model: current.model ?? model,
                    })}
              </span>
            </div>
            <Markdown text={current.content} />
          </div>
        ) : null}
      </div>
    </Card>
  );
}
