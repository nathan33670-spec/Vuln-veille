// Phase 5 exit criterion, driven in Chromium (see test_phase5_exit.py).
// Usage: node phase5_exit.cjs '<json config>'; exits non-zero on the first failed step.
"use strict";

const path = require("node:path");

const { signIn, step, watchProblems } = require("./browser_lib.cjs");

const config = JSON.parse(process.argv[2]);
const { chromium } = require(config.playwright);

async function dragHandle(page, from, to) {
  const a = await from.boundingBox();
  const b = await to.boundingBox();
  if (!a || !b) throw new Error("handle not visible");
  await page.mouse.move(a.x + a.width / 2, a.y + a.height / 2);
  await page.mouse.down();
  await page.mouse.move(b.x + 10, b.y + 10, { steps: 10 });
  await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2, { steps: 5 });
  await page.mouse.up();
}

(async () => {
  const browser = await chromium.launch({ executablePath: config.chromium });
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  const problems = [];
  watchProblems(page, problems);
  try {
    await step("sign in with the second factor", async () => {
      await signIn(page, config.base, config);
      await page.getByRole("link", { name: "Workflows" }).click();
    });

    await step("open the delivered workflow in the editor", async () => {
      await page.getByRole("link", { name: config.workflow }).click();
      await page.getByRole("link", { name: "Ouvrir l'éditeur" }).click();
      await page.locator("[data-testid=node-attach]").waitFor();
    });

    await step("add an agent of the workspace, wired after the analysis", async () => {
      await page.getByRole("button", { name: "Agent IA de l'espace" }).click();
      await page.locator("[data-testid=node-agent]").waitFor();
      const agent = page.getByLabel("Agent", { exact: true });
      const forums = agent.locator("option", { hasText: "Forums techniques" });
      await agent.selectOption((await forums.getAttribute("value")) ?? "");
      await page.getByLabel("Clé de sortie").fill("forums_after");
      await page.locator(".react-flow__controls-fitview").click();
      await page.waitForTimeout(500);
      await dragHandle(
        page,
        page.locator("[data-testid=node-attach] .react-flow__handle-right"),
        page.locator("[data-testid=node-agent] .react-flow__handle-left"),
      );
      await page.locator(".react-flow__edge").nth(21).waitFor(); // 21 delivered + 1
    });

    await step("change the notification filter", async () => {
      await page.locator("[data-testid=node-urgent]").click();
      const editor = page.locator(".vv-code-field .cm-content").first();
      await editor.click();
      await page.keyboard.press("ControlOrMeta+a");
      await page.keyboard.type("json.kev || json.base_score >= `9`");
      await page.keyboard.press("Escape");
      await page.getByText(/Brouillon enregistré/).waitFor({ timeout: 10000 });
    });

    await step("test the filter alone on a catalogue CVE", async () => {
      await page.getByRole("tab", { name: "Tester" }).click();
      await page.getByLabel("CVE du catalogue").fill(config.cve);
      await page.getByLabel("Forme de l'élément").selectOption("summary");
      await page.getByRole("button", { name: "Épingler cette CVE" }).click();
      await page.getByText("1 élément épinglé").waitFor();
      await page.getByRole("button", { name: "Tester ce nœud" }).click();
      await page.getByText("Port « true » : 1 élément(s)").waitFor({ timeout: 20000 });
      await page.screenshot({ path: path.join(config.artifacts, "tested.png") });
    });

    await step("publish the new version, with its changes listed", async () => {
      await page.getByRole("button", { name: "Publier une version" }).first().click();
      const dialog = page.locator("dialog[open]");
      await dialog.getByText("Changements").waitFor();
      await dialog.getByText("params.condition").waitFor();
      await dialog.getByLabel("Commentaire").fill("Agent forums sur les avis et seuil CVSS");
      await dialog.getByRole("button", { name: "Publier une version" }).click();
      await page.getByText(/Version 2 enregistrée/).waitFor();
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
