// Phase 7 exit criterion, driven in Chromium (see test_phase7_exit.py).
// Usage: node phase7_exit.cjs '<json config>'; exits non-zero on the first failed step.
"use strict";

const path = require("node:path");

const { signIn, step, watchProblems } = require("./browser_lib.cjs");

const config = JSON.parse(process.argv[2]);
const { chromium } = require(config.playwright);

(async () => {
  const browser = await chromium.launch({ executablePath: config.chromium });
  const page = await browser.newPage({ viewport: { width: 1500, height: 1000 } });
  const problems = [];
  watchProblems(page, problems);
  try {
    await step("sign in and store the target's token in the vault", async () => {
      await signIn(page, config.base, config);
      await page.getByRole("link", { name: "Secrets", exact: true }).click();
      await page.getByRole("button", { name: "Ajouter un secret" }).click();
      const dialog = page.locator("dialog[open]");
      await dialog.getByLabel("Nom").fill("jeton-partenaire");
      await dialog.getByLabel("Usage").selectOption("connector");
      await dialog.getByLabel("Valeur").fill(config.vaultValue);
      await dialog.getByRole("button", { name: "Créer" }).click();
      await page.getByText("Secret enregistré.").waitFor();
    });

    await step("configure a connector for an API nobody knew in advance", async () => {
      await page.getByRole("link", { name: "Publication", exact: true }).click();
      await page.getByRole("link", { name: "Nouveau connecteur" }).click();
      await page.getByLabel("Nom", { exact: true }).fill("Partenaire");
      await page.getByLabel("URL de base").fill("https://api.partner.example");
      await page.getByLabel("Chemin", { exact: true }).fill("/v2/advisories");
      await page.getByLabel("Type").selectOption("bearer");
      await page.getByLabel("Clé ou jeton *").selectOption({ label: "jeton-partenaire" });
      await page.getByLabel("Identifiant distant (JMESPath)").fill("data.id");
      // The mapping is previewed by the server on the example bulletin.
      await page.getByText('"reference": "VOC-2026-0001"').waitFor({ timeout: 10000 });
      await page.getByRole("button", { name: "Créer le connecteur" }).click();
      await page.getByText("Connecteur enregistré.").waitFor();
      await page.getByRole("heading", { name: "Partenaire" }).waitFor();
    });

    await step("push the validated bulletin after reading the exact request", async () => {
      await page.goto(`${config.base}/bulletins/${config.bulletin}`);
      await page.getByRole("button", { name: "Pousser vers…" }).click();
      const dialog = page.locator("dialog[open]");
      await dialog.getByLabel("Connecteur").selectOption({ label: "Partenaire" });
      await dialog.getByText("Authorization: Bearer ••••••").waitFor();
      await dialog.getByText(`"reference": "${config.ref}"`).waitFor();
      await page.screenshot({ path: path.join(config.artifacts, "dry-run.png"), fullPage: true });
      await dialog.getByRole("button", { name: "Confirmer l'envoi" }).click();
      await dialog.getByText("Réussi").waitFor({ timeout: 20000 });
      await dialog.getByText("identifiant distant ADV-1").waitFor();
      await dialog.getByRole("button", { name: "Fermer" }).click();
    });

    await step("read the complete journal of the push", async () => {
      const journal = page.locator("table").filter({ hasText: "Partenaire" }).first();
      await journal.getByText("Réussi").waitFor({ timeout: 10000 });
      await journal.getByRole("button", { name: "Tentatives" }).click();
      await page.getByText("Tentative 1").waitFor();
      await page.getByText("Requête envoyée (expurgée)").click();
      await page.getByText("Authorization: Bearer ••••••").last().waitFor();
      await page.getByText("Extrait de la réponse").click();
      await page.getByText(/"id": ?"ADV-1"/).first().waitFor();
      if ((await page.content()).includes(config.vaultValue))
        throw new Error("the token is visible in the interface");
      await page.screenshot({ path: path.join(config.artifacts, "journal.png"), fullPage: true });
    });

    if (problems.length) throw new Error(`browser errors: ${problems.join(" | ")}`);
    process.stdout.write("ok\n");
  } catch (error) {
    await page.screenshot({ path: path.join(config.artifacts, "failure.png") }).catch(() => {});
    process.stdout.write(`FAILED: ${error.message}\nscreenshot: ${config.artifacts}\n`);
    process.exitCode = 1;
  } finally {
    await browser.close();
  }
})();
