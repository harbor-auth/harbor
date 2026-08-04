// SPDX-License-Identifier: Apache-2.0

// Regression coverage for the plain HTML/CSS half of task 14's defect (1):
// rerun QA found that the documented disabled anchor pattern
// (`aria-disabled="true"` + `pointer-events: none` from
// ../css/sign-in-button.css) blocked mouse clicks but stayed in sequential
// Tab order and still navigated on Enter, because `pointer-events` only
// affects pointer/mouse activation, not keyboard focus order or a native
// `<a href>`'s default Enter-key action.
//
// The fix (see ../html/example.html and the updated comment above
// `.phb-button[aria-disabled="true"]` in ../css/sign-in-button.css) is
// structural, not CSS: the disabled anchor omits `href` entirely (nothing
// to navigate to, and an `<a>` without `href` is not natively focusable),
// adds `tabindex="-1"` as belt-and-suspenders, and adds `role="link"`
// because dropping `href` also drops the implicit ARIA "link" role.
//
// This file loads the actual committed ../html/example.html and
// ../css/sign-in-button.css through jsdom (reusing this package's existing
// vitest+jsdom setup rather than standing up a separate test harness for
// one static file) so the assertions below exercise the real shipped
// markup, not a hand-copied fixture.
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import userEvent from "@testing-library/user-event";

const here = path.dirname(fileURLToPath(import.meta.url));
const htmlPath = path.join(here, "..", "html", "example.html");
const cssPath = path.join(here, "..", "css", "sign-in-button.css");

function loadExampleDoc(): Document {
  const html = fs.readFileSync(htmlPath, "utf8");
  return new DOMParser().parseFromString(html, "text/html");
}

describe("plain HTML/CSS disabled button is genuinely inert", () => {
  it("the enabled example anchor keeps href, default Tab order, and no aria-disabled", () => {
    const doc = loadExampleDoc();
    const anchors = Array.from(doc.querySelectorAll("a.phb-button"));
    expect(anchors.length, "expected both an enabled and a disabled example anchor in example.html").toBe(2);

    const enabled = anchors[0];
    expect(enabled.getAttribute("href")).toBe("/auth/login");
    expect(enabled.hasAttribute("aria-disabled")).toBe(false);
    expect(enabled.hasAttribute("tabindex")).toBe(false);
  });

  it("the disabled example anchor has no href, is tabindex=-1, and keeps link semantics", () => {
    const doc = loadExampleDoc();
    const anchors = Array.from(doc.querySelectorAll("a.phb-button"));
    const disabled = anchors[1];

    // No href: nothing to navigate to, and per the HTML spec an <a> without
    // href does not participate in the default Tab order at all.
    expect(disabled.hasAttribute("href")).toBe(false);
    expect(disabled.getAttribute("aria-disabled")).toBe("true");
    // Explicit tabindex="-1": belt-and-suspenders against the same markup
    // gaining an href later and silently becoming tabbable again.
    expect(disabled.getAttribute("tabindex")).toBe("-1");
    // role="link": dropping href also drops the implicit ARIA link role;
    // this keeps the disabled control announced as a (disabled) link
    // rather than a bare, role-less <span>-equivalent.
    expect(disabled.getAttribute("role")).toBe("link");
    expect(disabled.getAttribute("aria-label")).toBe("Sign in with Private Harbor");

    // The inlined SVG root also needs its own aria-disabled="true" to pick
    // up the generated disabled colors (see ../css/sign-in-button.css and
    // ../gen/generate.go's disabled selector, which key off the SVG root's
    // own [aria-disabled="true"], not the wrapping anchor's).
    const svg = disabled.querySelector("svg");
    expect(svg?.getAttribute("aria-disabled")).toBe("true");
  });

  it("Tab from before the buttons skips the disabled anchor entirely and lands after it", async () => {
    const doc = loadExampleDoc();
    // Swap in the parsed body so real DOM focus/tab semantics (document,
    // activeElement, tabindex handling) apply the same way they do for the
    // React tests in ./disabled-and-focus.test.tsx.
    document.body.innerHTML = doc.body.innerHTML;

    const user = userEvent.setup();
    const anchors = Array.from(document.querySelectorAll("a.phb-button"));
    const [enabled, disabled] = anchors;

    (enabled as HTMLElement).focus();
    expect(document.activeElement).toBe(enabled);

    await user.tab();
    // The disabled anchor (no href, tabindex="-1") must never receive
    // focus via Tab.
    expect(document.activeElement).not.toBe(disabled);
  });

  it("the disabled anchor cannot be reached or activated by keyboard even when focus is attempted directly", async () => {
    const doc = loadExampleDoc();
    document.body.innerHTML = doc.body.innerHTML;

    const disabled = document.querySelectorAll("a.phb-button")[1] as HTMLAnchorElement;
    let navigated = false;
    disabled.addEventListener("click", () => {
      navigated = true;
    });

    // Attempting to focus it programmatically does nothing useful for
    // keyboard users: it has no href, so Enter has nothing to activate
    // (@testing-library/user-event only dispatches a synthetic click for
    // Enter on an <a> that actually has an href — matching real browser
    // behavior).
    disabled.focus();
    const user = userEvent.setup();
    await user.keyboard("{Enter}");
    expect(navigated).toBe(false);
  });

  it("css/sign-in-button.css documents pointer-events:none as insufficient on its own for keyboard inertness", () => {
    const css = fs.readFileSync(cssPath, "utf8");
    const rule = css.match(/\.phb-button\[aria-disabled="true"\]\s*\{([^}]*)\}/);
    expect(rule, "missing .phb-button[aria-disabled=\"true\"] rule in css/sign-in-button.css").not.toBeNull();
    expect(rule![1]).toMatch(/pointer-events:\s*none/);
  });
});

describe("plain HTML/CSS focus-visible ring forwarding (css/sign-in-button.css)", () => {
  const RING_BY_VARIANT: Record<string, string> = {
    light: "#1857c4",
    dark: "#7eb2ff",
    neutral: "#ffffff",
  };

  for (const [variant, ring] of Object.entries(RING_BY_VARIANT)) {
    it(`variant=${variant}: forwards the wrapping link's :focus-visible state to the SVG ring`, () => {
      const css = fs.readFileSync(cssPath, "utf8");
      const escaped = `phb-button--${variant}`;
      const rule = css.match(
        new RegExp(`\\.${escaped}:focus-visible \\.phb-btn-${variant}-ring\\s*\\{([^}]*)\\}`),
      );
      expect(rule, `missing .${escaped}:focus-visible ring-forwarding rule`).not.toBeNull();
      expect(rule![1].toLowerCase()).toMatch(new RegExp(`stroke:\\s*${ring}`));
    });
  }

  it("suppresses the default outline on the wrapping link so the forwarded ring is what's visible", () => {
    const css = fs.readFileSync(cssPath, "utf8");
    expect(css).toMatch(/\.phb-button:focus-visible\s*\{\s*outline:\s*none;\s*\}/);
  });
});
