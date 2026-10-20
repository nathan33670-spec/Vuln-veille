import { ApiError } from "@vv/api-client";
import type { TFunction } from "i18next";

/** Translates an API error code (``detail``) into a user-facing message. */
export function errorMessage(t: TFunction, error: unknown): string {
  if (error instanceof ApiError) {
    const key = `errors.${error.code}`;
    const translated = t(key);
    return translated === key ? t("errors.generic") : translated;
  }
  return t("errors.network");
}
