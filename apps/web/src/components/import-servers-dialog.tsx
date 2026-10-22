import { useMutation, useQueryClient } from "@tanstack/react-query";
import { type ChangeEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { ApiError, api } from "../lib/api.ts";
import type { Me } from "../lib/session.ts";
import type { HostImportResult } from "../lib/types.ts";
import { Alert } from "./ui/alert.tsx";
import { Button } from "./ui/button.tsx";
import { Dialog, DialogFooter } from "./ui/dialog.tsx";
import { TextAreaField } from "./ui/field.tsx";
import { useStepUp } from "./use-step-up.tsx";

/** A CSV file larger than this is refused before it is read (the API refuses the same size). */
const MAX_FILE_BYTES = 256 * 1024;

/**
 * Import of many servers at once: address, name and port per line (ADR 0011). The API checks
 * every row on its own; valid rows are added, duplicates skipped and the rest listed with the
 * reason, so a typo in one line does not hold back the others.
 */
export function ImportServersDialog({ open, me, onClose }: { open: boolean; me: Me; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const stepUp = useStepUp(me.user.email);
  const [csv, setCsv] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<HostImportResult | null>(null);

  const run = useMutation({
    mutationFn: (text: string) =>
      api<HostImportResult>("/hosts/import", { method: "POST", body: { csv: text } }),
    onMutate: () => setError(null),
    onSuccess: async (data) => {
      await queryClient.invalidateQueries({ queryKey: ["hosts"] });
      await queryClient.invalidateQueries({ queryKey: ["host-access"] });
      setResult(data);
    },
    onError: (e, text) => {
      if (stepUp.handled(e, () => run.mutate(text))) return;
      if (e instanceof ApiError && e.status === 422) {
        const code = e.problem?.errors?.[0]?.message ?? "";
        const key = `servers.fieldError.${code}`;
        return setError(i18n.exists(key) ? t(key as never) : t("servers.errorInvalid"));
      }
      setError(t("errors.actionFailed"));
    },
  });

  function close() {
    setCsv("");
    setError(null);
    setResult(null);
    onClose();
  }

  async function onFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = "";
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) return setError(t("servers.fieldError.csv_too_large"));
    setError(null);
    setCsv(await file.text());
  }

  const errorText = (code: string) => {
    const key = `servers.fieldError.${code}`;
    return i18n.exists(key) ? t(key as never) : code;
  };

  return (
    <>
      <Dialog
        open={open}
        onClose={close}
        title={result ? t("servers.importResultTitle") : t("servers.importTitle")}
        description={result ? undefined : t("servers.importDescription")}
      >
        {result ? (
          <div className="grid gap-4">
            <p className="font-medium">{t("servers.importCreated", { count: result.created.length })}</p>
            {result.created.length > 0 ? (
              <p className="text-muted-foreground">{t("servers.importNext")}</p>
            ) : null}
            {result.skipped.length > 0 ? (
              <section className="grid gap-1.5">
                <h3 className="text-sm font-medium">{t("servers.importSkipped")}</h3>
                <ul className="grid gap-1 text-sm">
                  {result.skipped.map((s) => (
                    <li key={s.line} className="break-all">
                      <span className="text-muted-foreground">
                        {t("servers.importLine", { line: s.line })}:{" "}
                      </span>
                      <span className="font-mono">{s.address}</span>
                      <span className="text-muted-foreground"> · {t(`servers.skipReason.${s.reason}`)}</span>
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}
            {result.invalid.length > 0 ? (
              <section className="grid gap-1.5">
                <h3 className="text-sm font-medium">{t("servers.importInvalid")}</h3>
                <ul className="grid gap-1 text-sm">
                  {result.invalid.map((row) => (
                    <li key={row.line} className="break-all">
                      <span className="text-muted-foreground">
                        {t("servers.importLine", { line: row.line })}:{" "}
                      </span>
                      <span className="font-mono">{row.address || "–"}</span>
                      <span className="text-destructive-text">
                        {" · "}
                        {row.errors.map((e) => errorText(e.code)).join(" ")}
                      </span>
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}
            <DialogFooter>
              <Button onClick={close}>{t("common.close")}</Button>
            </DialogFooter>
          </div>
        ) : (
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              run.mutate(csv);
            }}
          >
            {error ? <Alert tone="error">{error}</Alert> : null}
            <TextAreaField
              label={t("servers.importText")}
              name="csv"
              rows={8}
              value={csv}
              onChange={(e) => setCsv(e.currentTarget.value)}
              placeholder={"address,name,port\nweb-01.example.com,Web server,22"}
              autoComplete="off"
              spellCheck={false}
              className="font-mono text-sm"
            />
            <label className="grid gap-1.5 text-sm font-medium">
              {t("servers.importFile")}
              <input
                type="file"
                accept=".csv,text/csv,text/plain"
                onChange={(e) => void onFile(e)}
                className="text-sm font-normal"
              />
            </label>
            <DialogFooter>
              <Button variant="outline" onClick={close}>
                {t("common.cancel")}
              </Button>
              <Button type="submit" disabled={run.isPending || csv.trim() === ""}>
                {run.isPending ? t("common.loading") : t("servers.importSubmit")}
              </Button>
            </DialogFooter>
          </form>
        )}
      </Dialog>
      {stepUp.dialog}
    </>
  );
}
