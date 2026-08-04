// SPDX-License-Identifier: Apache-2.0

// Regression coverage for two accessibility defects rerun QA caught with
// attached browser evidence (task 14):
//
// 1. The React component documents standalone/zero-bundler use (see the
//    module doc comment in ./SignInWithPrivateHarborButton.tsx) but its
//    focus-ring forwarding rule (anchor `:focus-visible` -> SVG ring
//    `stroke`) previously existed only in ../css/sign-in-button.css, which
//    the component neither imports nor requires. Standalone light showed
//    the browser default outline; dark/neutral measured ~1.05:1/2.26:1
//    contrast instead of the intended >=3:1 ring, because the wrapping <a>
//    (the actually-focusable element — the inline SVG is
//    `focusable="false"`) never had its default outline suppressed nor its
//    focus-visible state forwarded down to the SVG ring. The fix embeds
//    that forwarding rule directly in the component's own per-variant
//    <style> string (VARIANT_STYLE), so it needs no external stylesheet.
// 2. Disabled React/HTML variants must be non-activatable and skipped by
//    Tab. This file also covers the React half of that (see
//    ../html/example.html and its own inertness fix for the plain
//    HTML/CSS half).
//
// jsdom's selector engine (nwsapi) does not implement `:focus-visible`
// matching, so `getComputedStyle` can't observe whether the forwarding
// rule actually applies on focus (see ./svg-style-scoping.test.tsx's file
// header for the same limitation with inline SVG <style> elements more
// generally). Instead this file asserts the forwarding rule's *text*
// is present in the component's own rendered <style> output — the same
// "resolve the flat, single-purpose selectors ourselves" approach already
// established in svg-style-scoping.test.tsx — and separately locks the
// content to the CSP hash table published in ../docs/INTEGRATION.md, so
// that table can't silently drift from what actually ships.
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  SignInWithPrivateHarborButton,
  type SignInWithPrivateHarborButtonVariant,
} from "./SignInWithPrivateHarborButton";

const here = path.dirname(fileURLToPath(import.meta.url));

const VARIANTS: SignInWithPrivateHarborButtonVariant[] = ["light", "dark", "neutral"];

// From gen/tokens.go Palettes[<scheme>].FocusRing.
const EXPECTED_FOCUS_RING: Record<SignInWithPrivateHarborButtonVariant, string> = {
  light: "#1857C4",
  dark: "#7EB2FF",
  neutral: "#FFFFFF",
};

function renderedStyleText(variant: SignInWithPrivateHarborButtonVariant): string {
  const { container } = render(<SignInWithPrivateHarborButton href="/auth/login" variant={variant} />);
  const styleEl = container.querySelector("style");
  expect(styleEl, `variant=${variant} rendered no <style> element`).not.toBeNull();
  return styleEl!.textContent ?? "";
}

describe("React component's own base .phb-button layout is self-contained (standalone/zero-bundler)", () => {
  for (const variant of VARIANTS) {
    it(`variant=${variant}: embeds the base .phb-button layout rule (display/line-height/border-radius/text-decoration), without importing css/sign-in-button.css`, () => {
      // Regression coverage: without this rule, a standalone consumer's
      // wrapping <a> falls back to default inline layout — its own
      // getBoundingClientRect() height comes out ~17px (the browser default
      // line-height for a 14px label) instead of the visually-painted 40px,
      // because nothing makes the anchor an inline-flex container sized to
      // its SVG child. The SVG still paints its full 40px (SVGs aren't
      // clipped by an undersized inline parent box) and click hit-testing
      // still works (DOM event bubbling doesn't require geometric box
      // containment), so this box-model inconsistency doesn't reproduce as
      // a visible defect — only as a wrong answer from the anchor's own
      // bounding box (e.g. code positioning a tooltip/overlay off it).
      const styleText = renderedStyleText(variant);

      expect(
        styleText,
        `variant=${variant} style is missing the base .phb-button layout rule`,
      ).toContain(
        `.phb-button--${variant}{display:inline-flex;line-height:0;border-radius:8px;text-decoration:none;}`,
      );
    });
  }

  for (const variant of VARIANTS) {
    it(`variant=${variant}: embeds its own outline-suppression + ring-forwarding rule, without importing css/sign-in-button.css`, () => {
      const styleText = renderedStyleText(variant);
      const ring = EXPECTED_FOCUS_RING[variant];

      // The wrapping <a> (phb-button--<variant>) is the focusable element —
      // the SVG is focusable="false" — so the default outline must be
      // suppressed on *that* selector, standalone, not left to an external
      // stylesheet.
      expect(
        styleText,
        `variant=${variant} style is missing the anchor default-outline suppression rule`,
      ).toContain(`.phb-button--${variant}:focus,.phb-button--${variant}:focus-visible{outline:none;}`);

      // ...and the anchor's :focus-visible state must forward to the SVG
      // ring with the exact >=3:1-contrast color from gen/tokens.go.
      expect(
        styleText,
        `variant=${variant} style is missing the anchor -> ring focus-visible forwarding rule`,
      ).toContain(`.phb-button--${variant}:focus-visible .phb-btn-${variant}-ring{stroke:${ring};}`);
    });
  }

  it("does not import ../css/sign-in-button.css (this test file doesn't either) — the component alone must supply the above rules", () => {
    const source = fs.readFileSync(path.join(here, "SignInWithPrivateHarborButton.tsx"), "utf8");
    expect(source).not.toMatch(/import\s+["'].*sign-in-button\.css["']/);
  });

  it("matches the CSP style-src hash table published in ../docs/INTEGRATION.md for every variant", () => {
    const integrationDoc = fs.readFileSync(path.join(here, "..", "docs", "INTEGRATION.md"), "utf8");

    for (const variant of VARIANTS) {
      const styleText = renderedStyleText(variant);
      const actualHash = `sha256-${createHash("sha256").update(styleText, "utf8").digest("base64")}`;

      const row = integrationDoc.match(
        new RegExp(`\\|\\s*\`${variant}\`\\s*\\|[^|]*\\|\\s*\`(sha256-[^\`]+)\`\\s*\\|`),
      );
      expect(row, `docs/INTEGRATION.md has no CSP hash table row for variant "${variant}"`).not.toBeNull();
      expect(
        actualHash,
        `docs/INTEGRATION.md's React CSP hash for "${variant}" has drifted from the component's actual rendered <style> content — recompute and update the table`,
      ).toBe(row![1]);
    }
  });
});

describe("disabled React variant is genuinely inert", () => {
  for (const variant of VARIANTS) {
    it(`variant=${variant}: disabled is removed from sequential Tab order and non-activatable by Enter`, async () => {
      const user = userEvent.setup();

      render(
        <>
          <button type="button">before</button>
          <SignInWithPrivateHarborButton href="/auth/login" variant={variant} disabled />
          <button type="button">after</button>
        </>,
      );

      const before = document.querySelector("button")!;
      const link = document.querySelector("a")!;
      const after = document.querySelectorAll("button")[1]!;

      expect(link).toHaveAttribute("tabindex", "-1");

      before.focus();
      expect(document.activeElement).toBe(before);

      // Tab from "before" must land on "after", skipping the disabled
      // button entirely — the regression this defect describes was the
      // disabled element staying in the sequential Tab order.
      await user.tab();
      expect(document.activeElement).toBe(after);

      // Even if something focuses the disabled link directly (tabindex="-1"
      // still permits *programmatic* focus), Enter must not activate it.
      // Capture the event object itself (not its .defaultPrevented value at
      // listener time) — React's onClick handler is a delegated listener
      // on an ancestor and runs *after* a same-target native listener
      // during the bubble phase, so reading .defaultPrevented inside the
      // listener would race ahead of React's preventDefault() call.
      link.focus();
      let clickEvent: Event | null = null;
      link.addEventListener("click", (e) => {
        clickEvent = e;
      });
      await user.keyboard("{Enter}");
      expect(clickEvent).not.toBeNull();
      expect(clickEvent!.defaultPrevented).toBe(true);
    });

    it(`variant=${variant}: enabled stays in Tab order and is activatable by Enter`, async () => {
      const user = userEvent.setup();

      render(
        <>
          <button type="button">before</button>
          <SignInWithPrivateHarborButton href="/auth/login" variant={variant} />
        </>,
      );

      const before = document.querySelector("button")!;
      const link = document.querySelector("a")!;

      expect(link).not.toHaveAttribute("tabindex");

      before.focus();
      await user.tab();
      expect(document.activeElement).toBe(link);

      let clickEvent: Event | null = null;
      link.addEventListener("click", (e) => {
        clickEvent = e;
      });
      await user.keyboard("{Enter}");
      expect(clickEvent).not.toBeNull();
      expect(clickEvent!.defaultPrevented).toBe(false);
    });
  }
});
