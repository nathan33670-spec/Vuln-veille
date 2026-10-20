import { createBackofficeClient } from "@vv/api-client";
import { useEffect, useState } from "react";

export type ApiHealth = "loading" | "ok" | "error";

const client = createBackofficeClient();

export function useApiHealth(): ApiHealth {
  const [state, setState] = useState<ApiHealth>("loading");
  useEffect(() => {
    let active = true;
    client
      .GET("/healthz")
      .then(({ data }) => active && setState(data?.status === "ok" ? "ok" : "error"))
      .catch(() => active && setState("error"));
    return () => {
      active = false;
    };
  }, []);
  return state;
}
