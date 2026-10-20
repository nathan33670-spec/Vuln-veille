import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import { afterEach } from "vitest";

import { authFr } from "./i18n";

void i18n.use(initReactI18next).init({
  lng: "fr",
  resources: { fr: { translation: authFr } },
  interpolation: { escapeValue: false },
});

// jsdom has no modal dialogs: emulate the open state and the close event.
HTMLDialogElement.prototype.showModal ??= function (this: HTMLDialogElement) {
  this.open = true;
};
HTMLDialogElement.prototype.close ??= function (this: HTMLDialogElement) {
  this.open = false;
  this.dispatchEvent(new Event("close"));
};

afterEach(() => cleanup());
