import { createAuthApi, createPortalClient } from "@vv/api-client";

export const client = createPortalClient();
export const authApi = createAuthApi("/api/portal/v1");
