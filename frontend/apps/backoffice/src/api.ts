import { createAuthApi, createBackofficeClient } from "@vv/api-client";

export const client = createBackofficeClient();
export const authApi = createAuthApi("/api/v1");
