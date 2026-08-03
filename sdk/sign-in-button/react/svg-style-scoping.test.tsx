// SPDX-License-Identifier: Apache-2.0

// Regression coverage for a defect visual QA caught in the browser
// preflight: every generated button SVG's embedded <style> block declared
// the *same* selectors (a single shared "phb-btn" class), regardless of
// color scheme. Selectors in a <style> element — including one nested
// inside an inline <svg> — are not scoped to that element's subtree; they
// match anywhere in the document. So once more than one variant's SVG was
// present in the same document, whichever variant's <style> block came
// last in the DOM won the cascade for every instance's fill/stroke colors
// (QA evidence: react-matrix-full.png, raw-svg-collision-test.png,
// react-focus-elem-crop.png attached to the visual-QA task). The fix
// scopes the generated class name per color scheme (`phb-btn-<scheme>`
// instead of `phb-btn`), in both ../gen/generate.go (and therefore every
// file under ../assets/) and this package's React component.
//
// jsdom does not populate `document.styleSheets` for inline SVG <style>
// elements, so `getComputedStyle` can't observe the cascade here. Instead
// this file resolves the cascade itself: for the flat, single-purpose
// selectors this generator emits, "last declaration for an identical
// selector string wins" is not an approximation of the browser algorithm,
// it *is* the browser algorithm (equal specificity, tie-broken by source
// order) — and is exactly the mechanism the bug depended on.
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import {
  SignInWithPrivateHarborButton,
  type SignInWithPrivateHarborButtonSize,
  type SignInWithPrivateHarborButtonVariant,
} from "./SignInWithPrivateHarborButton";

const here = path.dirname(fileURLToPath(import.meta.url));
const assetsDir = path.join(here, "..", "assets");

const VARIANTS: SignInWithPrivateHarborButtonVariant[] = ["light", "dark", "neutral"];
const SIZES: SignInWithPrivateHarborButtonSize[] = ["compact", "full"];
const DISABLED_STATES = [false, true];

// From gen/tokens.go Palettes[<scheme>].{Default,Disabled}.Background.
const EXPECTED_BG_FILL: Record<SignInWithPrivateHarborButtonVariant, string> = {
  light: "#FFFFFF",
  dark: "#14161C",
  neutral: "#0B4F8A",
};
const EXPECTED_DISABLED_BG_FILL: Record<SignInWithPrivateHarborButtonVariant, string> = {
  light: "#F5F6F8",
  dark: "#1B1D24",
  neutral: "#8FA9BD",
};

function resolveCascade(cssText: string): Map<string, string> {
  const winners = new Map<string, string>();
  const ruleRe = /([^{}]+)\{([^{}]*)\}/g;
  let match: RegExpExecArray | null;
  while ((match = ruleRe.exec(cssText)) !== null) {
    const [, selectorList, declarations] = match;
    for (const selector of selectorList.split(",")) {
      // Last declaration for a given selector string wins — see file
      // header: for these flat, equal-specificity selectors this *is* the
      // real cascade, not an approximation of it.
      winners.set(selector.trim(), declarations.trim());
    }
  }
  return winners;
}

function fillOf(cascade: Map<string, string>, selector: string): string | undefined {
  const declarations = cascade.get(selector);
  if (declarations === undefined) return undefined;
  return declarations.match(/fill:\s*(#[0-9A-Fa-f]{6})/)?.[1];
}

describe("generated SVG <style> scoping — cross-instance collision regression", () => {
  it("keeps each vendored asset SVG's own background fill when every variant/size is inlined into one document together", () => {
    const combos = VARIANTS.flatMap((variant) => SIZES.map((size) => ({ variant, size })));

    let combinedMarkup = "";
    for (const { variant, size } of combos) {
      combinedMarkup += fs.readFileSync(path.join(assetsDir, `button-${variant}-${size}.svg`), "utf8");
    }
    document.body.innerHTML = combinedMarkup;

    const svgEls = document.body.querySelectorAll("svg");
    expect(svgEls.length).toBe(combos.length);

    const allStyleText = Array.from(document.body.querySelectorAll("style"))
      .map((el) => el.textContent ?? "")
      .join("\n");
    const cascade = resolveCascade(allStyleText);

    svgEls.forEach((svg, i) => {
      const { variant } = combos[i];
      const bgRect = svg.querySelector("rect");
      const bgClass = Array.from(bgRect?.classList ?? []).find((c) => c.endsWith("-bg"));
      expect(bgClass, `asset svg #${i} (${variant}) has no -bg rect class`).toBeDefined();
      expect(
        fillOf(cascade, `.${bgClass}`),
        `asset svg #${i} (${variant}) resolved to the wrong background fill once every variant shared one document`,
      ).toBe(EXPECTED_BG_FILL[variant]);
    });
  });

  it("keeps each React instance's own background fill across the full variant x size x disabled matrix rendered together", () => {
    const combos = VARIANTS.flatMap((variant) =>
      SIZES.flatMap((size) => DISABLED_STATES.map((disabled) => ({ variant, size, disabled }))),
    );

    const { container } = render(
      <>
        {combos.map((c, i) => (
          <SignInWithPrivateHarborButton key={i} href="/auth/login" variant={c.variant} size={c.size} disabled={c.disabled} />
        ))}
      </>,
    );

    const svgEls = container.querySelectorAll("svg");
    expect(svgEls.length).toBe(combos.length);

    const allStyleText = Array.from(container.querySelectorAll("style"))
      .map((el) => el.textContent ?? "")
      .join("\n");
    const cascade = resolveCascade(allStyleText);

    svgEls.forEach((svg, i) => {
      const combo = combos[i];
      const btnClass = `phb-btn-${combo.variant}`;
      expect(svg.getAttribute("class")).toBe(btnClass);

      const selector = combo.disabled ? `.${btnClass}[aria-disabled="true"] .${btnClass}-bg` : `.${btnClass}-bg`;
      const expectedFill = combo.disabled ? EXPECTED_DISABLED_BG_FILL[combo.variant] : EXPECTED_BG_FILL[combo.variant];
      expect(
        fillOf(cascade, selector),
        `matrix instance #${i} (${JSON.stringify(combo)}) resolved to the wrong background fill once the full matrix shared one document`,
      ).toBe(expectedFill);
    });
  });
});
