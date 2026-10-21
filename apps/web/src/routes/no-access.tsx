import { useQueryClient } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { AuthLayout } from "../components/auth-layout.tsx";
import { Alert } from "../components/ui/alert.tsx";
import { Button } from "../components/ui/button.tsx";
import { authClient } from "../lib/auth-client.ts";
import { guard } from "../lib/guard.ts";

export const Route = createFileRoute("/no-access")({
  beforeLoad: ({ context }) => guard(context.queryClient, ["no-organization"]),
  component: NoAccess,
});

function NoAccess() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  return (
    <AuthLayout title={t("signIn.title")}>
      <div className="grid gap-4">
        <Alert tone="info">{t("errors.noOrganization")}</Alert>
        <Button
          variant="outline"
          onClick={async () => {
            await authClient.signOut();
            await queryClient.invalidateQueries();
            await navigate({ to: "/sign-in" });
          }}
        >
          {t("common.signOut")}
        </Button>
      </div>
    </AuthLayout>
  );
}
