import createClient, { type Middleware } from "openapi-fetch";

import type { paths as BackofficePaths } from "./backoffice";
import type { paths as PortalPaths } from "./portal";

export type { BackofficePaths, PortalPaths };

const CSRF_HEADER = "X-CSRF-Token";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Reads the CSRF token the server exposes in a <meta> tag (wired in phase 1). */
function csrfToken(): string | undefined {
  return document.querySelector<HTMLMetaElement>('meta[name="csrf-token"]')?.content || undefined;
}

const csrfMiddleware: Middleware = {
  onRequest({ request }) {
    const token = csrfToken();
    if (!SAFE_METHODS.has(request.method) && token) {
      request.headers.set(CSRF_HEADER, token);
    }
    return request;
  },
};

// Same-origin only: session cookies are HttpOnly and never readable from JavaScript.
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
