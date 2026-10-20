import createClient, { type Middleware } from "openapi-fetch";

import type { components as BackofficeComponents, paths as BackofficePaths } from "./backoffice";
import { ApiError, csrfHeaders } from "./http";
import type { components as PortalComponents, paths as PortalPaths } from "./portal";

export type { BackofficePaths, PortalPaths };
export type Schemas = BackofficeComponents["schemas"];
export type PortalSchemas = PortalComponents["schemas"];
export { ApiError, setCsrfToken } from "./http";
export { createAuthApi } from "./auth";
export type { AccountSession, AuthApi, Enrollment, LoginResult, Me, RecoveryCodes } from "./auth";

const csrfMiddleware: Middleware = {
  onRequest({ request }) {
    for (const [name, value] of Object.entries(csrfHeaders(request.method))) {
      request.headers.set(name, value);
    }
    return request;
  },
};

interface Problem {
  detail?: unknown;
}

/** Turns an openapi-fetch result into data or a thrown ApiError. */
export function unwrap<T>(result: { data?: T; error?: unknown; response: Response }): T {
  if (result.response.ok) return result.data as T;
  const detail = (result.error as Problem | undefined)?.detail;
  throw new ApiError(
    result.response.status,
    typeof detail === "string" ? detail : `http_${result.response.status}`,
  );
}

const baseOptions = {
  // Absolute same-origin URLs: relative URLs are not valid for the Fetch API outside a document.
  baseUrl: globalThis.location?.origin ?? "",
  credentials: "same-origin" as const,
  // Resolved at call time (not captured at import), so tests and wrappers can replace fetch.
  fetch: (request: Request) => globalThis.fetch(request),
};

export function createBackofficeClient() {
  const client = createClient<BackofficePaths>(baseOptions);
  client.use(csrfMiddleware);
  return client;
}

export function createPortalClient() {
  const client = createClient<PortalPaths>(baseOptions);
  client.use(csrfMiddleware);
  return client;
}

export type BackofficeClient = ReturnType<typeof createBackofficeClient>;
export type PortalClient = ReturnType<typeof createPortalClient>;
