import "./styles.css";
import "./lib/i18n.ts";
import "./lib/theme.ts";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createRouter, parseSearchWith, RouterProvider, stringifySearchWith } from "@tanstack/react-router";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { routeTree } from "./routeTree.gen.ts";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: true } },
});

// Plain search params (`?kev=1&severity=critical`) instead of JSON-encoded values, so shared
// links stay readable. The zod schemas in lib/search.ts parse and coerce every value.
const plain = (value: unknown) => value;
const router = createRouter({
  routeTree,
  context: { queryClient },
  defaultPreload: "intent",
  parseSearch: parseSearchWith(plain),
  stringifySearch: stringifySearchWith(String, plain),
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

const root = document.getElementById("root");
if (!root) throw new Error("Missing #root element");
createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
