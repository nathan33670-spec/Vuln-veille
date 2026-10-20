import { AuthProvider } from "@vv/auth";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { createBrowserRouter, RouterProvider } from "react-router";

import { authApi } from "./api";
import { routes } from "./routes";

export function App({ router }: { router?: ReturnType<typeof createBrowserRouter> }) {
  const [queryClient] = useState(
    () => new QueryClient({ defaultOptions: { queries: { refetchOnWindowFocus: false } } }),
  );
  const [browserRouter] = useState(() => router ?? createBrowserRouter(routes));
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider api={authApi} appKind="backoffice">
        <RouterProvider router={browserRouter} />
      </AuthProvider>
    </QueryClientProvider>
  );
}
