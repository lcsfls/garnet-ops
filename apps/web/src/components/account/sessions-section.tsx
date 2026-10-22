import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LogOut } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { type SessionRow, sessionsQuery } from "../../lib/account.ts";
import { api } from "../../lib/api.ts";
import { formatDateTime, formatRelative } from "../../lib/format.ts";
import { toast } from "../../lib/toast.ts";
import { Card, CardHeader } from "../page-header.tsx";
import { QueryStatus } from "../query-state.tsx";
import { Alert } from "../ui/alert.tsx";
import { Badge } from "../ui/badge.tsx";
import { Button } from "../ui/button.tsx";
import { ConfirmDialog } from "../ui/confirm-dialog.tsx";

/** Account → Sessions: where the account is signed in; end one session or all the others. */
export function SessionsSection() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const query = useQuery(sessionsQuery);
  const [ending, setEnding] = useState<SessionRow | null>(null);
  const [endingOthers, setEndingOthers] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["account", "sessions"] });

  const end = useMutation({
    mutationFn: (id: string) => api(`/account/sessions/${id}`, { method: "DELETE" }),
    onSuccess: async () => {
      setEnding(null);
      await refresh();
    },
    onError: () => setError(t("errors.generic")),
  });
  const endOthers = useMutation({
    mutationFn: () => api<{ revoked: number }>("/account/sessions/revoke-others", { method: "POST" }),
    onSuccess: async (result) => {
      setEndingOthers(false);
      toast.success(t("account.sessions.revoked", { count: result.revoked }));
      await refresh();
    },
    onError: () => setError(t("errors.generic")),
  });

  const label = (s: SessionRow) =>
    s.device.browser && s.device.os
      ? t("account.sessions.deviceLabel", { browser: s.device.browser, os: s.device.os })
      : s.device.browser || s.device.os || t("account.sessions.unknownDevice");
  const others = query.data?.filter((s) => !s.current).length ?? 0;

  return (
    <Card>
      <CardHeader
        title={t("account.sessions.title")}
        description={t("account.sessions.description")}
        actions={
          <Button
            variant="outline"
            disabled={others === 0}
            onClick={() => {
              setError(null);
              setEndingOthers(true);
            }}
          >
            <LogOut aria-hidden="true" className="size-4" />
            {t("account.sessions.revokeOthers")}
          </Button>
        }
      />
      <div className="grid gap-4 px-5 pb-5">
        {error ? <Alert tone="error">{error}</Alert> : null}
        {query.data ? (
          <ul className="grid gap-2">
            {query.data.map((s) => (
              <li
                key={s.id}
                data-testid="session"
                data-current={s.current ? "true" : undefined}
                className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-md border px-3 py-2.5"
              >
                <div className="min-w-0 flex-[1_1_16rem]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate font-medium">{label(s)}</span>
                    {s.current ? <Badge tone="info">{t("account.sessions.current")}</Badge> : null}
                  </div>
                  <div className="text-sm text-muted-foreground">
                    {s.ip ? <span className="font-mono">{s.ip}</span> : null}
                    {s.ip ? " · " : null}
                    {t("account.sessions.signedIn")}{" "}
                    <time dateTime={s.createdAt}>{formatDateTime(s.createdAt)}</time>
                    {" · "}
                    {t("account.sessions.lastActive")}{" "}
                    <time dateTime={s.lastActiveAt} title={formatDateTime(s.lastActiveAt)}>
                      {formatRelative(s.lastActiveAt)}
                    </time>
                  </div>
                </div>
                {s.current ? null : (
                  <Button
                    variant="outline"
                    className="h-9 px-3 text-sm"
                    onClick={() => {
                      setError(null);
                      setEnding(s);
                    }}
                  >
                    {t("account.sessions.signOut")}
                  </Button>
                )}
              </li>
            ))}
          </ul>
        ) : (
          <QueryStatus query={query} className="px-0" />
        )}
        {query.data && others === 0 ? (
          <p className="text-muted-foreground">{t("account.sessions.none")}</p>
        ) : null}
        <p className="text-sm text-muted-foreground">{t("account.sessions.lastActiveNote")}</p>
      </div>
      <ConfirmDialog
        open={ending !== null}
        title={t("account.sessions.signOutTitle")}
        description={t("account.sessions.signOutText")}
        confirmLabel={t("account.sessions.signOut")}
        pending={end.isPending}
        onConfirm={() => ending && end.mutate(ending.id)}
        onClose={() => setEnding(null)}
      />
      <ConfirmDialog
        open={endingOthers}
        title={t("account.sessions.revokeOthersTitle")}
        description={t("account.sessions.revokeOthersText")}
        confirmLabel={t("account.sessions.revokeOthersConfirm")}
        pending={endOthers.isPending}
        onConfirm={() => endOthers.mutate()}
        onClose={() => setEndingOthers(false)}
      />
    </Card>
  );
}
