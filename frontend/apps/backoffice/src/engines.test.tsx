import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { createMemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import "./i18n";
import { App } from "./App";
import { routes } from "./routes";

afterEach(() => {
  vi.unstubAllGlobals();
});

const me = {
  id: "u-eve",
  email: "eve@example.com",
  display_name: "Eve",
  user_type: "internal",
  locale: "fr",
  mfa_enabled: true,
  pending_mfa: false,
  csrf_token: "csrf",
  permissions: [],
  workspaces: [
    {
      slug: "cert",
      name: "CERT",
      role: "analyst",
      permissions: ["ai.engine.manage", "connector.source.manage", "secret.manage"],
    },
  ],
  client_org: null,
};

const OPENAI_TYPE = {
  kind: "openai_compatible",
  family: "ai_engine",
  label: "LLM compatible OpenAI (LLMaaS, vLLM, Ollama…)",
  scopes: ["global", "workspace"],
  cost_class: "ai_billed",
  egress_domains: [],
  secret_slots: [
    { name: "api_key", label: "Jeton d'accès (Bearer)", required: false },
    { name: "ca_bundle", label: "Autorité de certification PEM", required: false },
  ],
  config_schema: {
    properties: {
      base_url: { type: "string", title: "Base Url" },
      location: { type: "string", enum: ["external_cloud", "self_hosted"], default: "self_hosted" },
      timeout_seconds: { type: "integer", default: 180 },
      models: { type: "array" },
      data_classes: { type: "array" },
    },
  },
  default_quotas: {},
};

const CONNECTOR = {
  id: "c1",
  family: "ai_engine",
  kind: "openai_compatible",
  name: "LLM local",
  config: {
    base_url: "http://llm.cert.internal:11434/v1",
    location: "self_hosted",
    timeout_seconds: 180,
    data_classes: ["public", "tlp_clear"],
    models: [
      {
        model_id: "llama3",
        display_name: "",
        enabled: true,
        tools: "emulated",
        structured_output: "none",
        context_window: 32000,
        max_output_tokens: 4096,
      },
    ],
  },
  secret_refs: {},
  quotas: {},
  egress_domains: ["llm.cert.internal"],
  enabled: true,
  health: "unknown",
  last_check_at: null,
  last_success_at: null,
  last_error: null,
  consecutive_failures: 0,
  allow_private_network: false,
  private_network_cidrs: [],
  version: 1,
  created_at: "2026-10-23T08:00:00Z",
  updated_at: "2026-10-23T08:00:00Z",
};

type Call = { method: string; path: string; body: Record<string, unknown> | null };

function stubApi(calls: Call[]) {
  let polls = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const request = typeof input === "string" ? new Request(input, init) : input;
      const url = new URL(request.url);
      const raw = request.method === "GET" ? null : await request.clone().text();
      const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : null;
      calls.push({ method: request.method, path: url.pathname, body });
      const path = url.pathname;
      const base = "/api/v1/workspaces/cert/connectors/ai_engine";
      if (path === "/api/v1/auth/me") return Response.json(me);
      if (path === "/api/v1/connector-types") return Response.json([OPENAI_TYPE]);
      if (path === "/api/v1/workspaces/cert/secrets") return Response.json([]);
      if (path === base && request.method === "POST")
        return Response.json({ ...CONNECTOR, ...body, id: "c1" }, { status: 201 });
      if (path === `${base}/c1`) return Response.json(CONNECTOR);
      if (path === `${base}/c1/private-network`) return Response.json([]);
      if (path === `${base}/c1/probe`) return Response.json({ probe_id: "p1" }, { status: 202 });
      if (path === `${base}/c1/probe/p1`) {
        polls += 1;
        return Response.json(
          polls < 2
            ? { probe_id: "p1", status: "running", model_id: "llama3" }
            : {
                probe_id: "p1",
                status: "succeeded",
                model_id: "llama3",
                answer: "<b>Une CVE</b> est un identifiant de vulnérabilité.",
                model_served: "llama3:8b",
                input_tokens: 30,
                output_tokens: 12,
                duration_ms: 850,
              },
        );
      }
      return Response.json([]);
    }),
  );
}

function renderAt(path: string) {
  localStorage.setItem("vv.workspace", "cert");
  render(<App router={createMemoryRouter(routes, { initialEntries: [path] })} />);
}

describe("self-hosted AI engine", () => {
  it("declares an OpenAI-compatible server with its models", async () => {
    const calls: Call[] = [];
    stubApi(calls);
    renderAt("/ai-engines/new");
    fireEvent.change(await screen.findByLabelText("URL de base (compatible OpenAI)"), {
      target: { value: "http://llm.cert.internal:11434/v1" },
    });
    fireEvent.change(screen.getByLabelText("Identifiant du modèle"), {
      target: { value: "llama3" },
    });
    fireEvent.click(screen.getByLabelText("TLP:AMBER"));
    fireEvent.click(screen.getByRole("button", { name: "Créer le moteur" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
    const created = calls.find((c) => c.method === "POST");
    expect(created?.body).toMatchObject({
      kind: "openai_compatible",
      config: {
        base_url: "http://llm.cert.internal:11434/v1",
        location: "self_hosted",
        data_classes: ["public", "tlp_clear", "tlp_amber"],
        models: [{ model_id: "llama3", tools: "emulated", structured_output: "none" }],
      },
    });
  });

  it("asks the model a question and shows the answer as text", async () => {
    const calls: Call[] = [];
    stubApi(calls);
    renderAt("/ai-engines/c1");
    expect(
      await screen.findByRole("heading", { name: "Interroger le modèle" }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Plages (CIDR)")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Question"), { target: { value: "Une CVE ?" } });
    fireEvent.click(screen.getByRole("button", { name: "Envoyer" }));
    const answer = await screen.findByLabelText("Réponse du modèle", {}, { timeout: 4000 });
    expect(answer.textContent).toBe("<b>Une CVE</b> est un identifiant de vulnérabilité.");
    expect(answer.querySelector("b")).toBeNull();
    expect(screen.getByText(/llama3:8b · 30 jetons envoyés, 12 reçus/)).toBeInTheDocument();
    const probe = calls.find((c) => c.method === "POST" && c.path.endsWith("/probe"));
    expect(probe?.body).toEqual({ model_id: "llama3", prompt: "Une CVE ?" });
  });
});
