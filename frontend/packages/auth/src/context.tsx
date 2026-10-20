import { ApiError, type AuthApi, type Me, setCsrfToken } from "@vv/api-client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, type ReactNode, useCallback, useContext, useMemo } from "react";

interface AuthContextValue {
  api: AuthApi;
  /** "client" accounts may have no second factor; internal accounts always have one. */
  appKind: "backoffice" | "portal";
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({
  api,
  appKind,
  children,
}: AuthContextValue & { children: ReactNode }) {
  const value = useMemo(() => ({ api, appKind }), [api, appKind]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuthContext(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("AuthProvider missing");
  return value;
}

export const ME_KEY = ["auth", "me"] as const;

/** Current user; `null` when not signed in. Keeps the in-memory CSRF token in sync. */
export function useMe() {
  const { api } = useAuthContext();
  return useQuery<Me | null>({
    queryKey: ME_KEY,
    queryFn: async () => {
      try {
        const me = await api.me();
        setCsrfToken(me.csrf_token);
        return me;
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
          setCsrfToken(undefined);
          return null;
        }
        throw error;
      }
    },
    staleTime: 60_000,
    retry: false,
  });
}

export function useRefreshMe() {
  const queryClient = useQueryClient();
  return useCallback(() => queryClient.invalidateQueries({ queryKey: ME_KEY }), [queryClient]);
}

export function hasPermission(me: Me | null | undefined, permission: string): boolean {
  return Boolean(me && !me.pending_mfa && me.permissions.includes(permission));
}
