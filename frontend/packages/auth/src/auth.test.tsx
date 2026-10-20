import { ApiError, type AuthApi, type Me } from "@vv/api-client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { describe, expect, it, vi } from "vitest";

import { AuthProvider } from "./context";
import { LoginPage, RequireAuth } from "./pages";
import { StepUpProvider, useStepUp } from "./StepUp";

const baseMe: Me = {
  id: "u1",
  email: "ana@example.com",
  display_name: "Ana",
  user_type: "internal",
  locale: "fr",
  mfa_enabled: true,
  pending_mfa: false,
  permissions: [],
  workspaces: [],
  client_org: null,
  csrf_token: "csrf",
};

function fakeApi(overrides: Partial<AuthApi>): AuthApi {
  return {
    me: vi.fn(async () => {
      throw new ApiError(401, "not_authenticated");
    }),
    ...overrides,
  } as AuthApi;
}

function renderApp(api: AuthApi, element: ReactNode, path = "/") {
  const router = createMemoryRouter(
    [
      { path: "/login", element: <LoginPage /> },
      { path: "/mfa", element: <p>page mfa</p> },
      { path: "/mfa/enroll", element: <p>page enrôlement</p> },
      { element: <RequireAuth />, children: [{ path: "/", element }] },
    ],
    { initialEntries: [path] },
  );
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider api={api} appKind="backoffice">
        <RouterProvider router={router} />
      </AuthProvider>
    </QueryClientProvider>,
  );
}

describe("authentication screens", () => {
  it("sends a signed-in user with a pending second factor to the MFA page", async () => {
    let signedIn = false;
    const api = fakeApi({
      me: vi.fn(async () => {
        if (!signedIn) throw new ApiError(401, "not_authenticated");
        return { ...baseMe, pending_mfa: true };
      }),
      login: vi.fn(async () => {
        signedIn = true;
        return { status: "mfa_required" as const, csrf_token: "c" };
      }),
    });
    renderApp(api, <p>accueil</p>);
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Adresse e-mail"), "ana@example.com");
    await user.type(screen.getByLabelText("Mot de passe"), "correct horse battery");
    await user.click(screen.getByRole("button", { name: "Se connecter" }));
    expect(await screen.findByText("page mfa")).toBeInTheDocument();
    expect(api.login).toHaveBeenCalledWith("ana@example.com", "correct horse battery");
  });

  it("shows a generic error and clears the password on failure", async () => {
    const api = fakeApi({
      login: vi.fn(async () => {
        throw new ApiError(401, "invalid_credentials");
      }),
    });
    renderApp(api, <p>accueil</p>);
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Adresse e-mail"), "ana@example.com");
    await user.type(screen.getByLabelText("Mot de passe"), "wrong password");
    await user.click(screen.getByRole("button", { name: "Se connecter" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Identifiants incorrects");
    expect(screen.getByLabelText("Mot de passe")).toHaveValue("");
  });

  it("never renders protected content to an anonymous visitor", async () => {
    renderApp(fakeApi({}), <p>secret</p>);
    expect(await screen.findByRole("button", { name: "Se connecter" })).toBeInTheDocument();
    expect(screen.queryByText("secret")).not.toBeInTheDocument();
  });
});

function SensitiveAction({ action }: { action: () => Promise<unknown> }) {
  const withStepUp = useStepUp();
  return (
    <button type="button" onClick={() => void withStepUp(action).catch(() => undefined)}>
      sensible
    </button>
  );
}

describe("step-up", () => {
  it("asks for a code when the API requires it, then retries the action once", async () => {
    const stepUp = vi.fn(async () => ({ csrf_token: "c2" }));
    const api = fakeApi({ me: vi.fn(async () => baseMe), stepUp });
    let calls = 0;
    const action = vi.fn(async () => {
      calls += 1;
      if (calls === 1) throw new ApiError(403, "step_up_required");
      return "ok";
    });
    renderApp(
      api,
      <StepUpProvider>
        <SensitiveAction action={action} />
      </StepUpProvider>,
    );
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "sensible" }));
    await user.type(await screen.findByLabelText("Code"), "123456");
    await user.click(screen.getByText("Confirmer"));
    await waitFor(() => expect(stepUp).toHaveBeenCalledWith({ code: "123456" }));
    await waitFor(() => expect(action).toHaveBeenCalledTimes(2));
  });

  it("does not prompt for other errors", async () => {
    const api = fakeApi({ me: vi.fn(async () => baseMe) });
    const action = vi.fn(async () => {
      throw new ApiError(403, "forbidden");
    });
    renderApp(
      api,
      <StepUpProvider>
        <SensitiveAction action={action} />
      </StepUpProvider>,
    );
    await userEvent.setup().click(await screen.findByRole("button", { name: "sensible" }));
    await waitFor(() => expect(action).toHaveBeenCalledTimes(1));
    expect(screen.queryByLabelText("Code")).not.toBeInTheDocument();
  });
});
