import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import type { ExposureSettings } from "../lib/exposure.ts";
import { formatDateTime } from "../lib/format.ts";
import type { Me } from "../lib/session.ts";
import { toast } from "../lib/toast.ts";
import { Notice } from "./exposure-parts.tsx";
import { Card, CardHeader } from "./page-header.tsx";
import { QueryStatus } from "./query-state.tsx";
import { Alert } from "./ui/alert.tsx";
import { Badge } from "./ui/badge.tsx";
import { Button } from "./ui/button.tsx";
import { Checkbox } from "./ui/checkbox.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { useStepUp } from "./use-step-up.tsx";

/**
 * Settings, Exposure (ADR 0023): the one switch of the feature, the Certificate Transparency lookup. It sends the domain names of
 * verified assets to a public search service, so it is off until an owner or admin switches it on, knowing exactly what is sent where.
 */
export function ExposurePanel({ me }: { me: Me }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const canEdit = me.role === "owner" || me.role === "admin";
  const [asking, setAsking] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ["exposure", "settings"],
    queryFn: () => api<ExposureSettings>("/exposure/settings"),
  });
  const ct = query.data?.certificateTransparency;

  const save = useMutation({
    mutationFn: (enabled: boolean) =>
      api("/exposure/settings", {
        method: "PUT",
        body: { ct: { enabled, acknowledged: enabled ? acknowledged : undefined } },
      }),
    onMutate: () => setError(null),
    onSuccess: async (_data, enabled) => {
      await queryClient.invalidateQueries({ queryKey: ["exposure"] });
      setAsking(false);
      setAcknowledged(false);
      toast.success(t(enabled ? "exposure.ctSwitchedOn" : "exposure.ctSwitchedOff"));
    },
    onError: (e, enabled) => {
      if (stepUp.handled(e, () => save.mutate(enabled))) return;
      setError(
        e instanceof ApiError && e.status === 422
          ? t("exposure.ctNeedsAcknowledgement")
          : t("errors.actionFailed"),
      );
    },
  });

  return (
    <>
      <Card>
        <CardHeader title={t("exposure.settingsTitle")} description={t("exposure.settingsDescription")} />
        <div className="grid gap-3 px-5 pb-5">
          <QueryStatus query={query} />
          {!canEdit ? <Alert tone="info">{t("settings.readOnly")}</Alert> : null}
          {error && !asking ? <Alert tone="error">{error}</Alert> : null}
          {ct ? (
            <section
              className="grid gap-3 rounded-lg border p-4"
              aria-labelledby="ct-title"
              data-testid="ct-section"
            >
              <div className="flex flex-wrap items-center gap-2">
                <h3 id="ct-title" className="font-medium">
                  {t("exposure.ctTitle")}
                </h3>
                <Badge tone={ct.enabled ? "info" : "neutral"}>
                  {t(ct.enabled ? "exposure.ctOn" : "exposure.ctOff")}
                </Badge>
              </div>
              <p className="text-sm text-muted-foreground">{t("exposure.ctText")}</p>
              <Notice title={t("exposure.ctLeavesTitle", { provider: ct.provider.name })}>
                {t("exposure.ctLeavesText", { provider: ct.provider.name, operator: ct.provider.operator })}
              </Notice>
              <div className="grid gap-1">
                <span className="text-sm font-medium">{t("exposure.ctRequest")}</span>
                <code
                  data-testid="ct-url"
                  className="rounded-md border bg-muted/50 px-3 py-2 font-mono text-sm break-all"
                >
                  {ct.provider.urlTemplate}
                </code>
                <span className="text-sm text-muted-foreground">{t("exposure.ctRequestHint")}</span>
              </div>
              {ct.enabled ? (
                <p className="text-sm text-muted-foreground">
                  {t("exposure.ctEnabledBy", {
                    name: ct.enabledBy ?? "–",
                    when: ct.enabledAt ? formatDateTime(ct.enabledAt) : "–",
                  })}{" "}
                  {t("exposure.ctUsage", { used: ct.usageToday, budget: ct.dailyBudget })}
                </p>
              ) : null}
              {ct.lastError ? (
                <Alert tone="error">
                  {t(`exposure.ctError.${ct.lastError}` as never, { defaultValue: ct.lastError })}
                </Alert>
              ) : null}
              {canEdit ? (
                <div>
                  {ct.enabled ? (
                    <Button variant="outline" disabled={save.isPending} onClick={() => save.mutate(false)}>
                      {t("exposure.ctSwitchOff")}
                    </Button>
                  ) : (
                    <Button
                      onClick={() => {
                        setError(null);
                        setAsking(true);
                      }}
                    >
                      {t("exposure.ctSwitchOn")}
                    </Button>
                  )}
                </div>
              ) : null}
            </section>
          ) : null}
        </div>
      </Card>

      {ct ? (
        <Dialog
          open={asking}
          onClose={() => setAsking(false)}
          title={t("exposure.ctAskTitle", { provider: ct.provider.name })}
          description={t("exposure.ctAskDescription")}
        >
          <div className="grid gap-4">
            {error ? <Alert tone="error">{error}</Alert> : null}
            <Notice title={t("exposure.ctLeavesTitle", { provider: ct.provider.name })}>
              {t("exposure.ctLeavesText", { provider: ct.provider.name, operator: ct.provider.operator })}
            </Notice>
            <code className="rounded-md border bg-muted/50 px-3 py-2 font-mono text-sm break-all">
              {ct.provider.urlTemplate}
            </code>
            <p className="text-sm text-muted-foreground">
              {t("exposure.ctTermsNote", { provider: ct.provider.name })}
            </p>
            <label className="flex items-start gap-2.5 rounded-md border p-3">
              <Checkbox
                className="mt-1"
                checked={acknowledged}
                onChange={(e) => setAcknowledged(e.target.checked)}
              />
              <span>{t("exposure.ctAcknowledge", { provider: ct.provider.name })}</span>
            </label>
            <DialogFooter>
              <Button variant="outline" onClick={() => setAsking(false)}>
                {t("common.cancel")}
              </Button>
              <Button disabled={!acknowledged || save.isPending} onClick={() => save.mutate(true)}>
                {save.isPending ? t("common.loading") : t("exposure.ctSwitchOn")}
              </Button>
            </DialogFooter>
          </div>
        </Dialog>
      ) : null}
      {stepUp.dialog}
    </>
  );
}
