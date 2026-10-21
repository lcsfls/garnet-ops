import type { UseQueryResult } from "@tanstack/react-query";
import { RefreshCw } from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "../lib/cn.ts";
import { Alert } from "./ui/alert.tsx";
import { Button } from "./ui/button.tsx";

/**
 * Loading and error states of a query, so no page waits silently forever or
 * shows an empty table when the server could not be reached. The loading
 * block reserves room for a few rows, so the first data does not push the
 * page around much.
 */
export function QueryStatus({
  query,
  className,
}: {
  query: Pick<UseQueryResult, "data" | "isError" | "isFetching" | "refetch">;
  className?: string;
}) {
  const { t } = useTranslation();
  if (query.isError) {
    return (
      <div className={cn("px-5 py-5", className)}>
        <Alert tone="error">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <span>{query.data === undefined ? t("errors.loadFailed") : t("errors.refreshFailed")}</span>
            <Button
              variant="outline"
              className="h-8 px-3 text-sm"
              disabled={query.isFetching}
              onClick={() => void query.refetch()}
            >
              <RefreshCw aria-hidden="true" className="size-3.5" />
              {t("common.retry")}
            </Button>
          </div>
        </Alert>
      </div>
    );
  }
  if (query.data === undefined) {
    return (
      <p role="status" className={cn("min-h-40 px-5 py-6 text-muted-foreground", className)}>
        {t("common.loading")}
      </p>
    );
  }
  return null;
}
