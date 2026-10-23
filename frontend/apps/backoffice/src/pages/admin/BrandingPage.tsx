import { unwrap } from "@vv/api-client";
import { errorMessage, useStepUp } from "@vv/auth";
import { Alert, Button, Card, PageHeader, TextField } from "@vv/ui";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type ChangeEvent, type FormEvent, useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { client } from "../../api";

const MAX_LOGO_BYTES = 512 * 1024;

/** Base64 of a file, without the "data:…;base64," prefix. */
async function base64Of(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

/** Platform branding (Q46): the issuer's name and logo on the portal and in the PDFs. */
export function BrandingPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const withStepUp = useStepUp();
  const fileId = useId();
  const [message, setMessage] = useState<{ tone: "error" | "success"; text: string }>();
  const [issuer, setIssuer] = useState<string>();
  const branding = useQuery({
    queryKey: ["admin", "branding"],
    queryFn: async () => unwrap(await client.GET("/api/v1/admin/branding")),
  });

  async function run(action: () => Promise<unknown>, success: string) {
    try {
      await action();
      setMessage({ tone: "success", text: success });
      await queryClient.invalidateQueries({ queryKey: ["admin", "branding"] });
    } catch (err) {
      setMessage({ tone: "error", text: errorMessage(t, err) });
    }
  }

  if (branding.isPending) return <p className="vv-muted">{t("auth.loading")}</p>;
  if (branding.isError) return <Alert>{errorMessage(t, branding.error)}</Alert>;
  const b = branding.data;
  const name = issuer ?? b.issuer_name;

  async function saveName(event: FormEvent) {
    event.preventDefault();
    await run(async () => {
      unwrap(
        await client.PUT("/api/v1/admin/branding", {
          body: { issuer_name: name, version: b.version },
        }),
      );
      setIssuer(undefined);
    }, t("branding.saved"));
  }

  async function upload(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > MAX_LOGO_BYTES) {
      setMessage({ tone: "error", text: t("branding.tooLarge") });
      return;
    }
    const data = await base64Of(file);
    await run(
      () =>
        withStepUp(async () =>
          unwrap(
            await client.PUT("/api/v1/admin/branding/logo", {
              body: { data_base64: data, version: b.version },
            }),
          ),
        ),
      t("branding.logoSaved"),
    );
  }

  async function removeLogo() {
    await run(
      () =>
        withStepUp(async () =>
          unwrap(
            await client.DELETE("/api/v1/admin/branding/logo", {
              params: { query: { version: b.version } },
            }),
          ),
        ),
      t("branding.logoRemoved"),
    );
  }

  return (
    <>
      <PageHeader title={t("branding.title")} />
      {message ? <Alert tone={message.tone}>{message.text}</Alert> : null}
      <p className="vv-muted">{t("branding.explain")}</p>
      <Card title={t("branding.issuer")}>
        <form className="vv-filters" onSubmit={saveName}>
          <TextField
            label={t("branding.issuerName")}
            value={name}
            maxLength={120}
            onChange={(e) => setIssuer(e.target.value)}
          />
          <Button type="submit" disabled={name === b.issuer_name}>
            {t("branding.save")}
          </Button>
        </form>
      </Card>
      <Card title={t("branding.logo")}>
        {b.has_logo ? (
          <p>
            <img
              className="vv-brand-logo"
              alt={t("branding.currentLogo")}
              src={`/api/v1/admin/branding/logo?v=${b.version}`}
            />
          </p>
        ) : (
          <p className="vv-muted">{t("branding.noLogo")}</p>
        )}
        <div className="vv-actions">
          <div className="vv-field">
            <label htmlFor={fileId}>{t("branding.chooseLogo")}</label>
            <input
              id={fileId}
              type="file"
              accept="image/png,image/jpeg"
              onChange={(e) => void upload(e)}
            />
          </div>
          {b.has_logo ? (
            <Button variant="danger" onClick={() => void removeLogo()}>
              {t("branding.removeLogo")}
            </Button>
          ) : null}
        </div>
        <p className="vv-muted">{t("branding.logoHint")}</p>
      </Card>
    </>
  );
}
