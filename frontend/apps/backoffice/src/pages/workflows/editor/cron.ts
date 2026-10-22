import "cronstrue/locales/fr";

import cronstrue from "cronstrue";

/** A 5-field cron expression in plain French ("À 08:30, du lundi au vendredi"), or null. */
export function explainCron(expression: string): string | null {
  const fields = expression.trim().split(/\s+/);
  if (fields.length !== 5) return null;
  try {
    return cronstrue.toString(fields.join(" "), {
      locale: "fr",
      use24HourTimeFormat: true,
      throwExceptionOnParseError: true,
    });
  } catch {
    return null;
  }
}
