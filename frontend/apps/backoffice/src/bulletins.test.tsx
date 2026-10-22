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
  id: "u-ana",
  email: "ana@example.com",
  display_name: "Ana",
  user_type: "internal",
  locale: "fr",
  mfa_enabled: true,
  pending_mfa: false,
  csrf_token: "csrf",
  permissions: ["vuln.read"],
  workspaces: [
    {
      slug: "voc",
      name: "VOC",
      role: "analyst",
      permissions: [
        "bulletin.draft",
        "bulletin.review",
        "bulletin.publish",
        "template.manage",
        "workspace.settings.manage",
      ],
    },
  ],
  client_org: null,
};
const hostile = "<img src=x onerror=alert(1)>";

const spec = {
  language: "fr",
  priority: 0,
  tlp: "AMBER",
  match_rules: [],
  style_guide: "",
  example: "",
  render_template: "# {{ fields.title }}",
  fields: [
    { key: "title", label: "Titre", type: "text", required: true, generation: { mode: "ai" } },
    {
      key: "severity",
      label: "Sévérité",
      type: "enum",
      options: ["critical", "high", "medium", "low"],
      generation: { mode: "computed", from: "vuln.severity" },
    },
    {
      key: "summary",
      label: "Résumé",
      type: "markdown",
      required: true,
      generation: { mode: "ai" },
    },
    { key: "analyst_note", label: "Note", type: "markdown", generation: { mode: "manual" } },
  ],
};

function bulletin(overrides: Record<string, unknown> = {}) {
  return {
    id: "b1",
    ref: "VOC-2026-0001",
    title: "RCE dans Log4j",
    status: "draft",
    severity: "critical",
    tlp: "AMBER",
    language: "fr",
    workspace_slug: "voc",
    own: true,
    author_id: "u-ana",
    current_rev_no: 1,
    published_rev_no: null,
    published_at: null,
    updated_at: "2026-10-22T08:00:00Z",
    version: 1,
    audience_type: "all_clients",
    audience_org_ids: [],
    template_id: "t1",
    template_name: "Générique (FR)",
    template_version_no: 1,
    template_spec: spec,
    review_required: false,
    submitted_by: null,
    reviewer_id: null,
    approved_at: null,
    withdrawn_reason: null,
    current: {
      rev_no: 1,
      created_by_type: "ai",
      created_by: null,
      agent_run_id: "ar1",
      change_note: "Draft généré",
      content_hash: "h",
      created_at: "2026-10-22T08:00:00Z",
      fields: { title: "RCE dans Log4j", severity: "critical", summary: hostile, analyst_note: "" },
      rendered_markdown: "# RCE dans Log4j",
      rendered_html: `<h1>RCE dans Log4j</h1><p>&lt;img src=x&gt;</p>${hostile}<a href="javascript:alert(1)">x</a>`,
    },
    revisions: [
      {
        rev_no: 1,
        created_by_type: "ai",
        created_by: null,
        agent_run_id: "ar1",
        change_note: "Draft généré",
        content_hash: "h",
        created_at: "2026-10-22T08:00:00Z",
      },
    ],
    vulnerabilities: [{ id: "v1", ref: "VV-2026-0001", cve_id: "CVE-2026-6001", title: "Log4j" }],
    technologies: [],
    translation_of: null,
    translations: [],
    ...overrides,
  };
}

type Call = { method: string; path: string; body: unknown };
type Handler = (path: string, method: string, body: unknown) => Response | undefined;

function stubApi(calls: Call[], handler: Handler) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string, init?: RequestInit) => {
      const request = typeof input === "string" ? new Request(input, init) : input;
      const url = new URL(request.url);
      const raw = request.method === "GET" ? null : await request.clone().text();
      const body = raw ? (JSON.parse(raw) as unknown) : null;
      calls.push({ method: request.method, path: url.pathname, body });
      if (url.pathname === "/api/v1/auth/me") return Response.json(me);
      return handler(url.pathname, request.method, body) ?? Response.json([]);
    }),
  );
}

function renderAt(path: string) {
  render(<App router={createMemoryRouter(routes, { initialEntries: [path] })} />);
}

describe("bulletin screens", () => {
  it("requests a draft from a vulnerability and opens the bulletin once written", async () => {
    const calls: Call[] = [];
    let polls = 0;
    stubApi(calls, (path, method) => {
      if (path === "/api/v1/workspaces/voc/draft-requests" && method === "POST")
        return Response.json(
          {
            id: "d1",
            kind: "draft",
            status: "queued",
            progress: [],
            template_name: "Vulnérabilité exploitée ou critique (FR)",
            template_version_no: 1,
            selection_reasons: ["kev: true"],
            bulletin_id: null,
            agent_run_id: null,
            error: null,
            requested_by: "u-ana",
            created_at: "2026-10-22T08:00:00Z",
            finished_at: null,
          },
          { status: 202 },
        );
      if (path === "/api/v1/workspaces/voc/draft-requests/d1") {
        polls += 1;
        const done = polls > 1;
        return Response.json({
          id: "d1",
          kind: "draft",
          status: done ? "succeeded" : "running",
          progress: done ? [{ step: "context" }, { step: "done" }] : [{ step: "context" }],
          template_name: "Vulnérabilité exploitée ou critique (FR)",
          template_version_no: 1,
          selection_reasons: ["kev: true"],
          bulletin_id: done ? "b1" : null,
          agent_run_id: null,
          error: null,
          requested_by: "u-ana",
          created_at: "2026-10-22T08:00:00Z",
          finished_at: null,
        });
      }
      if (path === "/api/v1/workspaces/voc/bulletins/b1") return Response.json(bulletin());
      return undefined;
    });
    renderAt("/bulletins?vulnerability=v1&label=CVE-2026-6001");
    expect(await screen.findByText("CVE-2026-6001")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Consignes complémentaires"), {
      target: { value: "Insister sur la détection." },
    });
    fireEvent.click(screen.getByRole("button", { name: "Lancer la rédaction" }));
    expect(await screen.findByText(/kev: true/)).toBeInTheDocument();
    expect(await screen.findByText("Contexte rassemblé")).toBeInTheDocument();
    // Once the bulletin exists, its page opens.
    expect(
      await screen.findByRole(
        "heading",
        { name: "VOC-2026-0001 — RCE dans Log4j" },
        { timeout: 4000 },
      ),
    ).toBeInTheDocument();
    const sent = calls.find((c) => c.method === "POST" && c.path.endsWith("/draft-requests"));
    expect(sent?.body).toMatchObject({
      vulnerability_ids: ["v1"],
      cve_id: null,
      extra_instructions: "Insister sur la détection.",
      template_id: null,
    });
  });

  it("renders the bulletin safely and saves an edit as a new revision", async () => {
    const calls: Call[] = [];
    stubApi(calls, (path, method) => {
      if (path === "/api/v1/workspaces/voc/bulletins/b1") return Response.json(bulletin());
      if (path === "/api/v1/workspaces/voc/bulletin-templates/preview")
        return Response.json({
          fields: {},
          markdown: "",
          html: "<p>aperçu</p>",
          matches: null,
          reasons: [],
        });
      if (path === "/api/v1/workspaces/voc/bulletins/b1/revisions" && method === "POST")
        return Response.json(
          {
            type: "about:blank",
            title: "Unprocessable",
            status: 422,
            detail: "invalid_fields",
            errors: [{ path: "fields.summary", code: "missing" }],
          },
          { status: 422 },
        );
      return undefined;
    });
    renderAt("/bulletins/b1");
    const note = await screen.findByLabelText("Note");
    // Sanitized twice (server and DOMPurify): no image, no script link.
    expect(document.querySelector(".vv-bulletin img")).toBeNull();
    const links = [...document.querySelectorAll(".vv-bulletin a")].map((a) =>
      a.getAttribute("href"),
    );
    expect(links.some((href) => href?.startsWith("javascript:"))).toBe(false);
    // The hostile summary is a field value: plain text in a text area.
    expect((screen.getByLabelText("Résumé *") as HTMLTextAreaElement).value).toBe(hostile);

    fireEvent.change(note, { target: { value: "Vu avec l'équipe réseau." } });
    expect(await screen.findByText("aperçu", {}, { timeout: 3000 })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Enregistrer une révision" }));
    expect(await screen.findByText("Champ obligatoire")).toBeInTheDocument();
    const saved = calls.find((c) => c.method === "POST" && c.path.endsWith("/revisions"));
    expect(saved?.body).toMatchObject({
      base_rev_no: 1,
      fields: { analyst_note: "Vu avec l'équipe réseau.", severity: "critical" },
    });
  });

  it("lets only another analyst approve when double validation is on", async () => {
    const calls: Call[] = [];
    stubApi(calls, (path) => {
      if (path === "/api/v1/workspaces/voc/bulletins/b1")
        return Response.json(
          bulletin({ status: "in_review", review_required: true, submitted_by: "u-ana" }),
        );
      return undefined;
    });
    renderAt("/bulletins/b1");
    expect(
      await screen.findByText("En attente de la validation d'un autre analyste."),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Valider" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Renvoyer en brouillon" })).toBeEnabled();
  });

  it("shows the other team's bulletin read-only", async () => {
    stubApi([], (path) => {
      if (path === "/api/v1/workspaces/voc/bulletins/b2")
        return Response.json(
          bulletin({
            id: "b2",
            own: false,
            workspace_slug: "cert",
            status: "published",
            published_rev_no: 1,
            template_spec: null,
            template_name: null,
            revisions: [],
          }),
        );
      return undefined;
    });
    renderAt("/bulletins/b2");
    expect(await screen.findByText(/Publié par l'équipe CERT/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Enregistrer une révision" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Valider" })).toBeNull();
    expect(screen.getByText("Contenu (révision r1)")).toBeInTheDocument();
  });

  it("previews a template on a real vulnerability and saves a new version", async () => {
    const calls: Call[] = [];
    stubApi(calls, (path, method) => {
      if (path === "/api/v1/workspaces/voc/bulletin-templates/t1")
        return Response.json({
          id: "t1",
          name: "Générique (FR)",
          description: "",
          status: "active",
          is_default: true,
          language: "fr",
          priority: 0,
          tlp: "AMBER",
          rule_count: 0,
          seed_key: "generic_fr",
          active_version_no: 1,
          latest_version_no: 1,
          updated_at: "2026-10-22T08:00:00Z",
          version: 1,
          active_spec: spec,
          latest_spec: spec,
          versions: [
            {
              id: "tv1",
              version_no: 1,
              language: "fr",
              priority: 0,
              comment: "",
              created_by: null,
              created_at: "2026-10-22T08:00:00Z",
            },
          ],
        });
      if (path === "/api/v1/vulnerabilities")
        return Response.json({
          total: 1,
          items: [{ id: "v1", ref: "VV-2026-0001", cve_id: "CVE-2026-6001", title: "Log4j" }],
        });
      if (path === "/api/v1/workspaces/voc/bulletin-templates/preview")
        return Response.json({
          fields: {},
          markdown: "",
          html: "<h1>Aperçu serveur</h1>",
          matches: false,
          reasons: [],
        });
      if (path.endsWith("/versions") && method === "POST")
        return Response.json({ version_no: 2 }, { status: 201 });
      return undefined;
    });
    renderAt("/bulletin-templates/t1");
    expect(await screen.findByText("Aperçu serveur", {}, { timeout: 3000 })).toBeInTheDocument();
    await screen.findByRole("option", { name: /CVE-2026-6001/ });
    fireEvent.change(screen.getByLabelText("Aperçu sur"), { target: { value: "v1" } });
    await waitFor(
      () =>
        expect(
          calls.some(
            (c) =>
              c.path.endsWith("/preview") &&
              (c.body as { vulnerability_id?: string }).vulnerability_id === "v1",
          ),
        ).toBe(true),
      { timeout: 3000 },
    );
    expect(await screen.findByText(/Aucune règle de ce modèle ne correspond/)).toBeInTheDocument();

    const editor = screen.getByLabelText("Modèle (JSON)");
    fireEvent.change(editor, {
      target: { value: JSON.stringify({ ...spec, priority: 5 }, null, 2) },
    });
    const save = screen.getByRole("button", { name: "Enregistrer une nouvelle version" });
    await waitFor(() => expect(save).toBeEnabled(), { timeout: 3000 });
    fireEvent.click(save);
    await waitFor(() =>
      expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/versions"))).toBe(true),
    );
    const version = calls.find((c) => c.method === "POST" && c.path.endsWith("/versions"));
    expect(version?.body).toMatchObject({ base_version_no: 1, spec: { priority: 5 } });
  });

  it("saves the workspace settings (prefix and double validation)", async () => {
    const calls: Call[] = [];
    stubApi(calls, (path, method) => {
      if (path === "/api/v1/workspaces/voc/bulletin-templates")
        return Response.json([
          {
            id: "t1",
            name: "Générique (FR)",
            description: "",
            status: "active",
            is_default: true,
            language: "fr",
            priority: 0,
            tlp: "AMBER",
            rule_count: 0,
            seed_key: "generic_fr",
            active_version_no: 1,
            latest_version_no: 1,
            updated_at: "2026-10-22T08:00:00Z",
            version: 1,
          },
        ]);
      if (path === "/api/v1/workspaces/voc/bulletin-settings")
        return Response.json({
          ref_prefix: "VOC",
          review_required: false,
          default_template_id: "t1",
          updated_at: "2026-10-22T08:00:00Z",
          version: 1,
          ...(method === "PUT" ? { review_required: true, version: 2 } : {}),
        });
      return undefined;
    });
    renderAt("/bulletin-templates");
    fireEvent.click(await screen.findByLabelText(/Double validation/));
    fireEvent.click(screen.getByRole("button", { name: "Enregistrer" }));
    expect(await screen.findByText("Réglages enregistrés.")).toBeInTheDocument();
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.body).toEqual({
      ref_prefix: "VOC",
      review_required: true,
      default_template_id: "t1",
      version: 1,
    });
  });
});
