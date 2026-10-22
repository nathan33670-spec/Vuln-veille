// Phase 6 exit criterion, driven in Chromium (see test_phase6_exit.py).
// Usage: node phase6_exit.cjs '<json config>'; exits non-zero on the first failed step.
"use strict";

const path = require("node:path");

const { signIn, step, totp, watchProblems } = require("./browser_lib.cjs");

const config = JSON.parse(process.argv[2]);
const { chromium } = require(config.playwright);

(async () => {
  const browser = await chromium.launch({ executablePath: config.chromium });
  const problems = [];
  // Two analysts, two separate browser sessions.
  const author = await (await browser.newContext({ viewport: { width: 1500, height: 1000 } })).newPage();
  const reviewer = await (await browser.newContext({ viewport: { width: 1500, height: 1000 } })).newPage();
  watchProblems(author, problems);
  watchProblems(reviewer, problems);
  let current = author;
  try {
    await step("the author requests a draft on the CVE", async () => {
      await signIn(author, config.base, config.author);
      await author.getByRole("link", { name: "Bulletins", exact: true }).click();
      await author.getByRole("button", { name: "Demander un draft" }).click();
      const dialog = author.locator("dialog[open]");
      await dialog.getByLabel("Identifiant CVE").fill(config.cve);
      await dialog.getByRole("button", { name: "Lancer la rédaction" }).click();
    });

    await step("the template chosen by the rules is applied, then the bulletin opens", async () => {
      await author.getByText("Vulnérabilité exploitée ou critique (FR)").waitFor();
      await author.getByText(/Règle retenue : kev: true/).waitFor();
      await author.getByRole("heading", { name: /^VOC-\d{4}-0001 — / }).waitFor({ timeout: 30000 });
      await author.getByText("Brouillon", { exact: true }).first().waitFor();
      // Collected and generated content is never markup: no script in the rendering.
      if ((await author.locator(".vv-bulletin script").count()) !== 0)
        throw new Error("script element in the rendered bulletin");
      await author.screenshot({ path: path.join(config.artifacts, "draft.png"), fullPage: true });
    });

    await step("the author edits the draft, with the server preview", async () => {
      await author.getByLabel("Note de l'analyste", { exact: true }).fill("Vu avec l'équipe réseau.");
      await author.getByText("Aperçu (non enregistré)").waitFor();
      await author.locator(".vv-bulletin").getByText("Vu avec l'équipe réseau.").waitFor();
      await author.getByLabel("Note de modification").fill("Note de l'analyste");
      await author.getByRole("button", { name: "Enregistrer une révision" }).click();
      await author.getByText("Révision enregistrée.").waitFor();
    });

    await step("the author submits it and cannot validate it alone", async () => {
      await author.getByRole("button", { name: "Soumettre en relecture" }).click();
      await author.getByText("Bulletin soumis en relecture.").waitFor();
      await author.getByText("En attente de la validation d'un autre analyste.").waitFor();
      if (!(await author.getByRole("button", { name: "Valider" }).isDisabled()))
        throw new Error("the author could validate their own bulletin");
    });

    const url = author.url();
    current = reviewer;
    await step("a second analyst validates it", async () => {
      await signIn(reviewer, config.base, config.reviewer);
      await reviewer.getByRole("link", { name: "Bulletins", exact: true }).waitFor();
      await reviewer.goto(url);
      await reviewer.getByText("En relecture", { exact: true }).first().waitFor();
      await reviewer.getByRole("button", { name: "Valider" }).click();
      await reviewer.getByText("Bulletin validé.").waitFor();
    });

    await step("and publishes it, with a recent second factor", async () => {
      await reviewer.getByRole("button", { name: "Publier" }).click();
      const prompt = reviewer.locator("dialog[open]").filter({ hasText: "Confirmation requise" });
      const outcome = await Promise.race([
        reviewer.getByText("Bulletin publié.").waitFor().then(() => "published"),
        prompt.waitFor().then(() => "prompt"),
      ]);
      if (outcome === "prompt") {
        // The sign-in code cannot be replayed: the next window's code.
        await prompt.getByLabel("Code").fill(totp(config.reviewer.totpSecret, 1));
        await prompt.getByRole("button", { name: "Confirmer" }).click();
        await reviewer.getByText("Bulletin publié.").waitFor();
      }
      await reviewer.getByText("Publié", { exact: true }).first().waitFor();
      await reviewer.screenshot({ path: path.join(config.artifacts, "published.png"), fullPage: true });
    });

    if (problems.length) throw new Error(`browser errors: ${problems.join(" | ")}`);
    process.stdout.write("ok\n");
  } catch (error) {
    await current.screenshot({ path: path.join(config.artifacts, "failure.png") }).catch(() => {});
    process.stdout.write(`FAILED: ${error.message}\nscreenshot: ${config.artifacts}\n`);
    process.exitCode = 1;
  } finally {
    await browser.close();
  }
})();
