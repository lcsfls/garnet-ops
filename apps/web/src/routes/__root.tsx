import type { QueryClient } from "@tanstack/react-query";
import { createRootRouteWithContext, Link, Outlet } from "@tanstack/react-router";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { AuthLayout } from "../components/auth-layout.tsx";
import { Alert } from "../components/ui/alert.tsx";
import { Button } from "../components/ui/button.tsx";

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: Outlet,
  errorComponent: RootError,
  notFoundComponent: NotFound,
});

/** An address that does not exist, such as a bookmark to a module removed in 0.0.4 (ADR 0025). */
function NotFound() {
  const { t } = useTranslation();
  return (
    <AuthLayout title={t("notFound.title")}>
      <div className="grid gap-4">
        <p>{t("notFound.text")}</p>
        <Link to="/" className="text-primary-text underline-offset-4 hover:underline">
          {t("notFound.back")}
        </Link>
      </div>
    </AuthLayout>
  );
}

function RootError({ reset }: { reset: () => void }) {
  const { t } = useTranslation();
  // Comes back by itself, e.g. after an update restarted the API.
  useEffect(() => {
    const timer = setInterval(async () => {
      const ok = await fetch("/api/health", { cache: "no-store" })
        .then((r) => r.ok && Boolean(r.headers.get("content-type")?.includes("json")))
        .catch(() => false);
      if (ok) window.location.reload();
    }, 5000);
    return () => clearInterval(timer);
  }, []);
  return (
    <AuthLayout title={t("errors.generic")}>
      <div className="grid gap-4">
        <Alert tone="error">{t("errors.network")}</Alert>
        <p className="text-sm text-muted-foreground">{t("errors.reconnects")}</p>
        <Button onClick={() => reset()}>{t("common.continue")}</Button>
      </div>
    </AuthLayout>
  );
}
