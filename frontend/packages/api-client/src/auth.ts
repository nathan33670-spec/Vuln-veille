import { ApiError, csrfHeaders } from "./http";
import type { BackofficePaths, PortalPaths, Schemas } from "./index";

/**
 * Authentication and account endpoints shared by both applications (same schemas, the
 * paths only differ by prefix). The checks below fail to compile if a path disappears
 * from either generated OpenAPI schema.
 */
type AuthPath =
  | "/auth/login"
  | "/auth/mfa/verify"
  | "/auth/mfa/enroll"
  | "/auth/mfa/enroll/confirm"
  | "/auth/logout"
  | "/auth/me"
  | "/auth/invitation/accept"
  | "/auth/password/forgot"
  | "/auth/password/reset"
  | "/auth/step-up"
  | "/account/password"
  | "/account/sessions"
  | "/account/sessions/{session_id}"
  | "/account/mfa/recovery-codes"
  | "/account/mfa";
type Missing<P, Prefix extends string> = Exclude<`${Prefix}${AuthPath}`, keyof P>;
const backofficeHasAll: Missing<BackofficePaths, "/api/v1"> extends never ? true : never = true;
const portalHasAll: Missing<PortalPaths, "/api/portal/v1"> extends never ? true : never = true;
void backofficeHasAll;
void portalHasAll;

export type Me = Schemas["MeOut"];
export type LoginResult = Schemas["LoginOut"];
export type Enrollment = Schemas["EnrollmentOut"];
export type RecoveryCodes = Schemas["RecoveryCodesOut"];
export type AccountSession = Schemas["SessionOut"];

export interface AuthApi {
  login(email: string, password: string): Promise<LoginResult>;
  verifyMfa(code: string): Promise<{ csrf_token: string }>;
  startEnrollment(): Promise<Enrollment>;
  confirmEnrollment(code: string): Promise<RecoveryCodes>;
  me(): Promise<Me>;
  logout(): Promise<void>;
  acceptInvitation(token: string, password: string): Promise<void>;
  forgotPassword(email: string): Promise<void>;
  resetPassword(token: string, password: string): Promise<void>;
  stepUp(input: { code?: string; password?: string }): Promise<{ csrf_token: string }>;
  changePassword(currentPassword: string, newPassword: string): Promise<void>;
  listSessions(): Promise<AccountSession[]>;
  revokeSession(id: string): Promise<void>;
  regenerateRecoveryCodes(): Promise<RecoveryCodes>;
  disableMfa(): Promise<void>;
}

async function call<T>(method: string, url: string, body?: unknown): Promise<T> {
  const response = await globalThis.fetch(`${globalThis.location?.origin ?? ""}${url}`, {
    method,
    credentials: "same-origin",
    headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...csrfHeaders(method),
    },
    body: body === undefined ? null : JSON.stringify(body),
  });
  if (!response.ok) {
    let code = `http_${response.status}`;
    try {
      const problem = (await response.json()) as { detail?: unknown };
      if (typeof problem.detail === "string") code = problem.detail;
    } catch {
      // keep the generic code
    }
    throw new ApiError(response.status, code);
  }
  if (response.status === 204 || response.status === 202) return undefined as T;
  return (await response.json()) as T;
}

export function createAuthApi(prefix: "/api/v1" | "/api/portal/v1"): AuthApi {
  const p = (path: AuthPath) => `${prefix}${path}`;
  return {
    login: (email, password) => call("POST", p("/auth/login"), { email, password }),
    verifyMfa: (code) => call("POST", p("/auth/mfa/verify"), { code }),
    startEnrollment: () => call("POST", p("/auth/mfa/enroll")),
    confirmEnrollment: (code) => call("POST", p("/auth/mfa/enroll/confirm"), { code }),
    me: () => call("GET", p("/auth/me")),
    logout: () => call("POST", p("/auth/logout")),
    acceptInvitation: (token, password) =>
      call("POST", p("/auth/invitation/accept"), { token, password }),
    forgotPassword: (email) => call("POST", p("/auth/password/forgot"), { email }),
    resetPassword: (token, password) =>
      call("POST", p("/auth/password/reset"), { token, password }),
    stepUp: (input) => call("POST", p("/auth/step-up"), input),
    changePassword: (currentPassword, newPassword) =>
      call("POST", p("/account/password"), {
        current_password: currentPassword,
        new_password: newPassword,
      }),
    listSessions: () => call("GET", p("/account/sessions")),
    revokeSession: (id) =>
      call(
        "DELETE",
        p("/account/sessions/{session_id}").replace("{session_id}", encodeURIComponent(id)),
      ),
    regenerateRecoveryCodes: () => call("POST", p("/account/mfa/recovery-codes")),
    disableMfa: () => call("DELETE", p("/account/mfa")),
  };
}
