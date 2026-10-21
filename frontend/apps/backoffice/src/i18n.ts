import { authFr } from "@vv/auth";
import i18n from "i18next";
import { initReactI18next } from "react-i18next";

import fr from "./locales/fr.json";

void i18n.use(initReactI18next).init({
  lng: "fr",
  fallbackLng: "fr",
  resources: {
    fr: { translation: { ...authFr, ...fr, errors: { ...authFr.errors, ...fr.errors } } },
  },
  interpolation: { escapeValue: false }, // React already escapes output
});

export default i18n;
