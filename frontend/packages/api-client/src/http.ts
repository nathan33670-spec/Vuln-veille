const CSRF_HEADER = "X-CSRF-Token";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * The CSRF token comes from the API (login, MFA and /auth/me responses) and is kept in
 * memory only. The session cookie itself is HttpOnly and never readable from JavaScript.
 */
let csrfToken: string | undefined;

export function setCsrfToken(token: string | undefined): void {
  csrfToken = token;
}

export function csrfHeaders(method: string): Record<string, string> {
  return !SAFE_METHODS.has(method.toUpperCase()) && csrfToken ? { [CSRF_HEADER]: csrfToken } : {};
}

/** An API failure carrying the server's stable error code (RFC 9457 `detail`). */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string) {
    super(code);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}
