import DOMPurify from "dompurify";
import { useMemo } from "react";

const ALLOWED_URI = /^(?:https?:|mailto:)/i;

DOMPurify.addHook("afterSanitizeAttributes", (node) => {
  if (node.tagName === "A") {
    const href = node.getAttribute("href") ?? "";
    if (!ALLOWED_URI.test(href)) node.removeAttribute("href");
    node.setAttribute("rel", "noopener noreferrer nofollow");
    node.setAttribute("target", "_blank");
  }
});

/** Sanitizes untrusted HTML; returns a TrustedHTML value where Trusted Types are enforced. */
export function sanitizeHtml(dirty: string): string {
  return DOMPurify.sanitize(dirty, {
    USE_PROFILES: { html: true },
    FORBID_TAGS: ["style", "img", "iframe", "form", "input", "svg", "math"],
    FORBID_ATTR: ["style", "srcset"],
    ALLOW_DATA_ATTR: false,
    RETURN_TRUSTED_TYPE: true,
  }) as unknown as string;
}

export interface SafeHtmlProps {
  html: string;
  className?: string;
}

/** The only sanctioned way to render HTML coming from the API (already sanitized server-side). */
export function SafeHtml({ html, className }: SafeHtmlProps) {
  const clean = useMemo(() => sanitizeHtml(html), [html]);
  // eslint-disable-next-line no-restricted-syntax -- this component is the audited exception
  return <div className={className} dangerouslySetInnerHTML={{ __html: clean }} />;
}
