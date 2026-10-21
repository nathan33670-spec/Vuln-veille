import { type Schemas, unwrap } from "@vv/api-client";
import { errorMessage, hasPermission, useMe } from "@vv/auth";
import {
  Alert,
  Badge,
  Button,
  Card,
  DataTable,
  Dialog,
  PageHeader,
  SelectField,
  TextField,
} from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../api";
import { splitList } from "../../lib";

type Technology = Schemas["TechnologyOut"];
type Suggestion = Schemas["CpeSuggestionOut"];

export function TechnologiesPage() {
  const { t } = useTranslation();
  const me = useMe().data;
  const queryClient = useQueryClient();
  const [q, setQ] = useState("");
  const [draft, setDraft] = useState<Partial<Schemas["TechnologyCreate"]>>();
  const [merging, setMerging] = useState<Technology>();
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string }>();
  const canCurate = hasPermission(me, "technology.manage");
  const canMerge = hasPermission(me, "technology.merge_delete");
  const list = useQuery({
    queryKey: ["technologies", q],
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/technologies", {
          params: { query: { q: q || null, limit: 100 } },
        }),
      ),
  });
  const suggestions = useQuery({
    queryKey: ["cpe-suggestions", q],
    enabled: canCurate && q.length >= 2,
    queryFn: async () =>
      unwrap(
        await client.GET("/api/v1/technologies/cpe-suggestions", { params: { query: { q } } }),
      ),
  });

  async function act(action: () => Promise<unknown>, success: string) {
    try {
      await action();
      setMessage({ tone: "success", text: success });
      await queryClient.invalidateQueries({ queryKey: ["technologies"] });
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }

  return (
    <>
      <PageHeader
        title={t("technologies.title")}
        actions={
          canCurate ? <Button onClick={() => setDraft({})}>{t("technologies.add")}</Button> : null
        }
      />
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      <TextField
        label={t("common.search")}
        type="search"
        value={q}
        maxLength={100}
        onChange={(e) => setQ(e.target.value)}
      />
      <DataTable<Technology>
        rows={list.data ?? []}
        rowKey={(tech) => tech.id}
        empty={list.isPending ? t("auth.loading") : t("technologies.empty")}
        columns={[
          { key: "name", header: t("admin.name"), render: (tech) => tech.display_name },
          {
            key: "vp",
            header: t("technologies.vendorProduct"),
            render: (tech) => `${tech.vendor} / ${tech.product}`,
          },
          { key: "cpe", header: "CPE", render: (tech) => tech.cpe_prefixes.join(", ") || "—" },
          {
            key: "aliases",
            header: t("technologies.aliases"),
            render: (tech) => tech.aliases.join(", ") || "—",
          },
          {
            key: "status",
            header: t("admin.statusLabel"),
            render: (tech) => (
              <Badge tone={tech.status === "active" ? "ok" : "neutral"}>
                {t(`technologies.status.${tech.status}`)}
              </Badge>
            ),
          },
          ...(canMerge
            ? [
                {
                  key: "actions",
                  header: "",
                  render: (tech: Technology) => (
                    <span className="vv-actions">
                      <Button variant="secondary" onClick={() => setMerging(tech)}>
                        {t("technologies.merge")}
                      </Button>
                      <Button
                        variant="danger"
                        onClick={() =>
                          act(
                            async () =>
                              unwrap(
                                await client.DELETE("/api/v1/technologies/{technology_id}", {
                                  params: { path: { technology_id: tech.id } },
                                }),
                              ),
                            t("technologies.deleted"),
                          )
                        }
                      >
                        {t("common.remove")}
                      </Button>
                    </span>
                  ),
                },
              ]
            : []),
        ]}
      />
      {canCurate && (suggestions.data ?? []).length ? (
        <Card title={t("technologies.suggestions")}>
          <p className="vv-muted">{t("technologies.suggestionsHint")}</p>
          <DataTable<Suggestion>
            rows={suggestions.data ?? []}
            rowKey={(s) => s.cpe_prefix}
            empty=""
            columns={[
              { key: "cpe", header: "CPE", render: (s) => <code>{s.cpe_prefix}</code> },
              { key: "count", header: t("technologies.cveCount"), render: (s) => s.cve_count },
              {
                key: "add",
                header: "",
                render: (s) =>
                  s.existing_technology_id ? (
                    <Badge tone="ok">{t("technologies.known")}</Badge>
                  ) : (
                    <Button
                      variant="secondary"
                      onClick={() =>
                        setDraft({
                          vendor: s.vendor,
                          product: s.product,
                          display_name: `${s.vendor} ${s.product}`.replaceAll("_", " "),
                          cpe_prefixes: [s.cpe_prefix],
                        })
                      }
                    >
                      {t("technologies.addFromCpe")}
                    </Button>
                  ),
              },
            ]}
          />
        </Card>
      ) : null}
      <Dialog
        open={Boolean(draft)}
        title={t("technologies.add")}
        onClose={() => setDraft(undefined)}
      >
        {draft ? (
          <TechnologyForm
            initial={draft}
            onSubmit={(body) =>
              act(async () => {
                unwrap(await client.POST("/api/v1/technologies", { body }));
                setDraft(undefined);
              }, t("technologies.created"))
            }
            onCancel={() => setDraft(undefined)}
          />
        ) : null}
      </Dialog>
      <Dialog
        open={Boolean(merging)}
        title={t("technologies.merge")}
        onClose={() => setMerging(undefined)}
      >
        {merging ? (
          <MergeForm
            source={merging}
            candidates={(list.data ?? []).filter(
              (tech) => tech.id !== merging.id && tech.status !== "merged",
            )}
            onSubmit={(into) =>
              act(async () => {
                unwrap(
                  await client.POST("/api/v1/technologies/{technology_id}/merge", {
                    params: { path: { technology_id: merging.id } },
                    body: { into },
                  }),
                );
                setMerging(undefined);
              }, t("technologies.merged"))
            }
          />
        ) : null}
      </Dialog>
    </>
  );
}

function TechnologyForm({
  initial,
  onSubmit,
  onCancel,
}: {
  initial: Partial<Schemas["TechnologyCreate"]>;
  onSubmit: (body: Schemas["TechnologyCreate"]) => Promise<void>;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const [vendor, setVendor] = useState(initial.vendor ?? "");
  const [product, setProduct] = useState(initial.product ?? "");
  const [name, setName] = useState(initial.display_name ?? "");
  const [aliases, setAliases] = useState((initial.aliases ?? []).join(", "));
  const [cpes, setCpes] = useState((initial.cpe_prefixes ?? []).join(", "));
  const [purls, setPurls] = useState((initial.purls ?? []).join(", "));
  const [category, setCategory] = useState(initial.category ?? "");
  async function submit(event: FormEvent) {
    event.preventDefault();
    await onSubmit({
      vendor,
      product,
      display_name: name,
      aliases: splitList(aliases),
      cpe_prefixes: splitList(cpes),
      purls: splitList(purls),
      category,
    });
  }
  return (
    <form className="vv-form" onSubmit={submit}>
      <TextField
        label={t("technologies.vendor")}
        hint={t("technologies.nameHint")}
        value={vendor}
        required
        maxLength={100}
        onChange={(e) => setVendor(e.target.value)}
      />
      <TextField
        label={t("technologies.product")}
        hint={t("technologies.nameHint")}
        value={product}
        required
        maxLength={100}
        onChange={(e) => setProduct(e.target.value)}
      />
      <TextField
        label={t("technologies.displayName")}
        value={name}
        required
        maxLength={200}
        onChange={(e) => setName(e.target.value)}
      />
      <TextField
        label={t("technologies.aliases")}
        hint={t("scope.listHint")}
        value={aliases}
        onChange={(e) => setAliases(e.target.value)}
      />
      <TextField
        label={t("technologies.cpePrefixes")}
        hint="cpe:2.3:a:apache:log4j"
        value={cpes}
        onChange={(e) => setCpes(e.target.value)}
      />
      <TextField
        label={t("technologies.purls")}
        hint="pkg:maven/org.apache.logging.log4j/log4j-core"
        value={purls}
        onChange={(e) => setPurls(e.target.value)}
      />
      <TextField
        label={t("technologies.category")}
        value={category}
        maxLength={100}
        onChange={(e) => setCategory(e.target.value)}
      />
      <div className="vv-actions">
        <Button type="submit">{t("admin.create")}</Button>
        <Button variant="secondary" onClick={onCancel}>
          {t("auth.cancel")}
        </Button>
      </div>
    </form>
  );
}

function MergeForm({
  source,
  candidates,
  onSubmit,
}: {
  source: Technology;
  candidates: Technology[];
  onSubmit: (into: string) => Promise<void>;
}) {
  const { t } = useTranslation();
  const [into, setInto] = useState(candidates[0]?.id ?? "");
  return (
    <form
      className="vv-form"
      onSubmit={(e) => {
        e.preventDefault();
        void onSubmit(into);
      }}
    >
      <p>{t("technologies.mergeHint", { name: source.display_name })}</p>
      <SelectField
        label={t("technologies.mergeInto")}
        value={into}
        onChange={setInto}
        options={candidates.map((c) => ({ value: c.id, label: c.display_name }))}
      />
      <div className="vv-actions">
        <Button type="submit" disabled={!into}>
          {t("technologies.merge")}
        </Button>
      </div>
    </form>
  );
}
