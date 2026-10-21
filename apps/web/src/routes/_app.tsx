import { createFileRoute, Outlet } from "@tanstack/react-router";
import { AppShell } from "../components/app-shell.tsx";
import { guard } from "../lib/guard.ts";

/** Layout for every signed-in page: only users with a second factor and an organisation get here. */
export const Route = createFileRoute("/_app")({
  beforeLoad: async ({ context }) => {
    const status = await guard(context.queryClient, ["ready"]);
    if (status.kind !== "ready") throw new Error("guard let a non-ready status through");
    return { me: status.me };
  },
  component: AppLayout,
});

function AppLayout() {
  const { me } = Route.useRouteContext();
  return (
    <AppShell me={me}>
      <Outlet />
    </AppShell>
  );
}
