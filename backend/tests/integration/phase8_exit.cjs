// Phase 8 exit criterion, driven in Chromium against the portal (see test_phase8_exit.py).
// Usage: node phase8_exit.cjs '<json config>'; exits non-zero on the first failed step.
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const { signIn, step, watchProblems } = require("./browser_lib.cjs");

const config = JSON.parse(process.argv[2]);
const { chromium } = require(config.playwright);

async function assertHidden(page, where) {
  const content = await page.content();
  for (const title of config.hiddenTitles) {
    if (content.includes(title)) throw new Error(`${where}: "${title}" is visible`);
  }
}

(async () => {
  const browser = await chromium.launch({ executablePath: config.chromium });
  const context = await browser.newContext({
    viewport: { width: 1400, height: 1000 },
    acceptDownloads: true,
  });
  const page = await context.newPage();
  const problems = [];
  watchProblems(page, problems);
  try {
    await step("sign in to the portal, under the issuer's branding", async () => {
      await signIn(page, config.base, config);
      await page.getByRole("heading", { name: "Bulletins de sécurité" }).waitFor();
      await page.locator(".vv-brand").getByText("CERT Exemple").waitFor();
      const logo = page.locator("img.vv-brand-logo");
      await logo.waitFor();
      const width = await logo.evaluate((img) => img.naturalWidth);
      if (!width) throw new Error("the issuer's logo did not load");
    });

    await step("the list holds the organisation's bulletins, and nothing else", async () => {
      await page.getByRole("link", { name: "Faille pour tous" }).waitFor();
      await page.getByRole("link", { name: "Faille réservée Acme" }).waitFor();
      await assertHidden(page, "list");
      await page.screenshot({ path: path.join(config.artifacts, "list.png"), fullPage: true });
    });

    await step("search and filters, without surfacing hidden bulletins", async () => {
      await page.getByLabel("Recherche").fill("Faille");
      await page.getByRole("button", { name: "Rechercher" }).click();
      await page.getByRole("link", { name: "Faille pour tous" }).waitFor();
      await assertHidden(page, "search");
      await page.getByLabel("Sévérité").selectOption("low");
      await page.getByRole("button", { name: "Rechercher" }).click();
      await page.getByText("Aucun bulletin publié pour le moment", { exact: false }).waitFor();
      await page.getByRole("button", { name: "Réinitialiser" }).click();
      await page.getByRole("link", { name: "Faille réservée Acme" }).waitFor();
    });

    await step("read a bulletin, its history, export it as PDF and print it", async () => {
      await page.getByRole("link", { name: "Faille réservée Acme" }).click();
      await page.getByRole("heading", { name: /Faille réservée Acme/ }).first().waitFor();
      await page.getByText("TLP:AMBER").waitFor();
      await page.getByText(/Publication —/).waitFor();
      const [download] = await Promise.all([
        page.waitForEvent("download"),
        page.getByRole("link", { name: "PDF" }).click(),
      ]);
      const file = path.join(config.artifacts, download.suggestedFilename());
      await download.saveAs(file);
      if (!fs.readFileSync(file).subarray(0, 5).equals(Buffer.from("%PDF-")))
        throw new Error("the export is not a PDF");
      if (!download.suggestedFilename().endsWith(".pdf"))
        throw new Error(`unexpected file name ${download.suggestedFilename()}`);
      await page.getByRole("button", { name: "Imprimer" }).waitFor();
      await page.emulateMedia({ media: "print" });
      if (await page.locator(".vv-header").isVisible())
        throw new Error("the header is printed");
      await page.emulateMedia({ media: "screen" });
      await page.screenshot({ path: path.join(config.artifacts, "detail.png"), fullPage: true });
    });

    await step("the published version only, never the update in progress", async () => {
      await page.goto(`${config.base}/bulletins/${config.visible.everyone}`);
      await page.getByRole("heading", { name: /Faille pour tous/ }).first().waitFor();
      await assertHidden(page, "detail");
    });

    await step("a direct link to another organisation's or a RED bulletin shows nothing", async () => {
      for (const id of Object.values(config.hidden)) {
        await page.goto(`${config.base}/bulletins/${id}`);
        await page.getByRole("alert").waitFor();
        await page.getByRole("link", { name: "← Tous les bulletins" }).waitFor();
        await assertHidden(page, `direct link ${id}`);
      }
      for (const [id, format] of [
        [config.hidden.beta, "pdf"],
        [config.hidden.red, "html"],
      ]) {
        const response = await page.request.get(
          `${config.base}/api/portal/v1/bulletins/${id}/export?format=${format}`,
        );
        if (response.status() !== 404)
          throw new Error(`export of a hidden bulletin answered ${response.status()}`);
      }
    });

    await step("choose to receive the bulletins by e-mail", async () => {
      await page.getByRole("link", { name: "Notifications" }).click();
      const box = page.getByLabel("Recevoir les bulletins par e-mail");
      await box.waitFor();
      if (await box.isChecked()) throw new Error("e-mails must be off by default");
      await box.click(); // the box follows the saved state, once the server answers
      await page.getByText("Vous recevrez les bulletins par e-mail.").waitFor();
      await page.reload();
      await page.getByLabel("Recevoir les bulletins par e-mail").waitFor();
      if (!(await page.getByLabel("Recevoir les bulletins par e-mail").isChecked()))
        throw new Error("the preference was not saved");
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
