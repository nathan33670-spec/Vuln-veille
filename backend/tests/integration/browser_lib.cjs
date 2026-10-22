// Shared by the browser tests (see browser.py): second factor, steps, signing in.
"use strict";

const crypto = require("node:crypto");

/** The TOTP code of a base32 secret, `windows` steps of 30 s ahead. */
function totp(secret, windows = 0) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret.replace(/=+$/, "").toUpperCase()) {
    bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  }
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + windows));
  const mac = crypto.createHmac("sha1", key).update(counter).digest();
  const offset = mac[mac.length - 1] & 0xf;
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

async function step(name, action) {
  process.stdout.write(`- ${name}\n`);
  await action();
}

async function signIn(page, base, user) {
  await page.goto(`${base}/login`);
  await page.getByLabel("Adresse e-mail").fill(user.email);
  await page.getByLabel("Mot de passe").fill(user.password);
  await page.getByRole("button", { name: "Se connecter" }).click();
  await page.getByLabel("Code").fill(totp(user.totpSecret));
  await page.getByRole("button", { name: "Vérifier" }).click();
}

/** Console errors and page errors, except the expected 404s. */
function watchProblems(page, problems) {
  page.on("console", (m) => {
    if (m.type() === "error" && !m.text().includes("404")) problems.push(m.text());
  });
  page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));
}

module.exports = { signIn, step, totp, watchProblems };
