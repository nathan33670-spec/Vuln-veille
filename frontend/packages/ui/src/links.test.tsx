// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { ExternalLink, safeHttpUrl } from "./components";

afterEach(() => cleanup());

describe("links from collected data", () => {
  it("keeps only http(s) URLs", () => {
    expect(safeHttpUrl("https://example.org/a?b=1")).toBe("https://example.org/a?b=1");
    for (const bad of [
      "javascript:alert(1)",
      "JaVaScRiPt:alert(1)",
      "data:text/html,<script>",
      "/relative",
      "vbscript:x",
      "",
      null,
    ]) {
      expect(safeHttpUrl(bad)).toBeNull();
    }
  });

  it("renders hostile links as plain text and safe ones without referrer or opener", () => {
    render(
      <>
        <ExternalLink href="javascript:alert(1)">evil</ExternalLink>
        <ExternalLink href="https://example.org/poc">good</ExternalLink>
      </>,
    );
    expect(screen.getByText("evil").closest("a")).toBeNull();
    const good = screen.getByRole("link", { name: "good" });
    expect(good.getAttribute("rel")).toBe("noopener noreferrer nofollow");
    expect(good.getAttribute("target")).toBe("_blank");
  });
});
