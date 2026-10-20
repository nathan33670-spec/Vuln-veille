import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import "./i18n";
import { App } from "./App";

afterEach(() => vi.unstubAllGlobals());

describe("App", () => {
  it("shows the API status once /healthz answers", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ status: "ok", service: "test" })),
    );
    render(<App />);
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("API disponible"));
  });

  it("reports an unreachable API", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Promise.reject(new TypeError("network"))),
    );
    render(<App />);
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("API injoignable"));
  });
});
