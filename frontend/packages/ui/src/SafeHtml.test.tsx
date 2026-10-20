// @vitest-environment jsdom
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SafeHtml, sanitizeHtml } from "./SafeHtml";

describe("sanitizeHtml", () => {
  it("removes scripts, event handlers and javascript: links", () => {
    const dirty =
      '<p onclick="steal()">hi<script>alert(1)</script></p><a href="javascript:alert(1)">x</a>';
    const clean = String(sanitizeHtml(dirty));
    expect(clean).not.toContain("script");
    expect(clean).not.toContain("onclick");
    expect(clean).not.toContain("javascript:");
  });

  it("drops images and inline styles (no tracking, no CSS injection)", () => {
    const clean = String(sanitizeHtml('<img src="https://evil.example/p.gif"><b style="x">b</b>'));
    expect(clean).toBe("<b>b</b>");
  });

  it("hardens external links", () => {
    const { container } = render(<SafeHtml html='<a href="https://nvd.nist.gov">NVD</a>' />);
    const link = container.querySelector("a");
    expect(link?.getAttribute("rel")).toBe("noopener noreferrer nofollow");
    expect(link?.getAttribute("target")).toBe("_blank");
  });
});
