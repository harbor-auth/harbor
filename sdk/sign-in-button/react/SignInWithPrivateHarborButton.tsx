// SPDX-License-Identifier: Apache-2.0

/**
 * A dependency-light "Sign in with Private Harbor" button. The only peer
 * dependency is `react` — no CSS-in-JS runtime, no icon library.
 *
 * SVG sourcing: the markup below is an inline, byte-faithful reproduction
 * of the matching file under ../assets/ (button-{variant}-{size}.svg) and
 * reuses the exact class names from ../css/sign-in-button.css
 * (`phb-button*`, `phb-btn*`), the same pairing the plain HTML example in
 * ../html/example.html uses. It is inlined as JSX rather than imported
 * from ../assets/ so this file has zero bundler requirements (no SVGR, no
 * `?raw`/asset-source loader, no raw-loader config) and typechecks/renders
 * identically under any React toolchain. Consumers who would rather import
 * the vendored files directly may do so with their bundler's SVG-to-React
 * transform (e.g. SVGR) or a raw-text import (e.g. Vite's `?raw`,
 * webpack's `asset/source`) — see ../assets/ and ../css/sign-in-button.css.
 */

import * as React from "react";

export type SignInWithPrivateHarborButtonVariant = "light" | "dark" | "neutral";
export type SignInWithPrivateHarborButtonSize = "compact" | "full";

export interface SignInWithPrivateHarborButtonProps {
  /**
   * The RP's OWN login-initiation URL (e.g. "/auth/login"). Never an
   * `/authorize` URL — this component does not accept OIDC parameters
   * (no `state`, `nonce`, `code_challenge`, `client_id`, or
   * `redirect_uri` props exist). See ../docs/SECURITY.md.
   */
  href: string;
  variant?: SignInWithPrivateHarborButtonVariant;
  size?: SignInWithPrivateHarborButtonSize;
  disabled?: boolean;
  /**
   * Overrides the default accessible name; defaults to
   * "Sign in with Private Harbor". The visible label text on the `full`
   * size is fixed wording (spec REQ-001) and does not change with this
   * prop.
   */
  ariaLabel?: string;
}

const DEFAULT_LABEL = "Sign in with Private Harbor";

// Verbatim from the <style> block of each ../assets/button-<variant>-*.svg.
// Only fill/stroke colors differ between variants; geometry is shared and
// computed in the component below.
const VARIANT_STYLE: Record<SignInWithPrivateHarborButtonVariant, string> = {
  light:
    ".phb-btn-bg{fill:#FFFFFF;stroke:#D6D9DE;stroke-width:1;}" +
    ".phb-btn-ring{fill:none;stroke:transparent;stroke-width:2;}" +
    '.phb-btn-label,.phb-btn-icon{fill:#16181D;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}' +
    ".phb-btn-label{font-size:14px;font-weight:600;}" +
    ".phb-btn:hover .phb-btn-bg{fill:#F0F2F5;stroke:#C3C8D1;}" +
    ".phb-btn:focus-visible .phb-btn-ring{stroke:#1857C4;}" +
    '.phb-btn.phb-btn--disabled .phb-btn-bg,.phb-btn[aria-disabled="true"] .phb-btn-bg{fill:#F5F6F8;stroke:#E4E7EB;}' +
    '.phb-btn.phb-btn--disabled .phb-btn-label,.phb-btn.phb-btn--disabled .phb-btn-icon,.phb-btn[aria-disabled="true"] .phb-btn-label,.phb-btn[aria-disabled="true"] .phb-btn-icon{fill:#9AA1AC;}',
  dark:
    ".phb-btn-bg{fill:#14161C;stroke:#3A3E47;stroke-width:1;}" +
    ".phb-btn-ring{fill:none;stroke:transparent;stroke-width:2;}" +
    '.phb-btn-label,.phb-btn-icon{fill:#FFFFFF;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}' +
    ".phb-btn-label{font-size:14px;font-weight:600;}" +
    ".phb-btn:hover .phb-btn-bg{fill:#1E212A;stroke:#4B4F5A;}" +
    ".phb-btn:focus-visible .phb-btn-ring{stroke:#7EB2FF;}" +
    '.phb-btn.phb-btn--disabled .phb-btn-bg,.phb-btn[aria-disabled="true"] .phb-btn-bg{fill:#1B1D24;stroke:#2A2D35;}' +
    '.phb-btn.phb-btn--disabled .phb-btn-label,.phb-btn.phb-btn--disabled .phb-btn-icon,.phb-btn[aria-disabled="true"] .phb-btn-label,.phb-btn[aria-disabled="true"] .phb-btn-icon{fill:#6B6F79;}',
  neutral:
    ".phb-btn-bg{fill:#0B4F8A;stroke:#0B4F8A;stroke-width:1;}" +
    ".phb-btn-ring{fill:none;stroke:transparent;stroke-width:2;}" +
    '.phb-btn-label,.phb-btn-icon{fill:#FFFFFF;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}' +
    ".phb-btn-label{font-size:14px;font-weight:600;}" +
    ".phb-btn:hover .phb-btn-bg{fill:#0A4576;stroke:#0A4576;}" +
    ".phb-btn:focus-visible .phb-btn-ring{stroke:#FFFFFF;}" +
    '.phb-btn.phb-btn--disabled .phb-btn-bg,.phb-btn[aria-disabled="true"] .phb-btn-bg{fill:#8FA9BD;stroke:#8FA9BD;}' +
    '.phb-btn.phb-btn--disabled .phb-btn-label,.phb-btn.phb-btn--disabled .phb-btn-icon,.phb-btn[aria-disabled="true"] .phb-btn-label,.phb-btn[aria-disabled="true"] .phb-btn-icon{fill:#E8EEF3;}',
};

const SIZE_DIMENSIONS: Record<SignInWithPrivateHarborButtonSize, { width: number; iconTranslateX: number }> = {
  compact: { width: 40, iconTranslateX: 10 },
  full: { width: 240, iconTranslateX: 16 },
};

const HEIGHT = 40;

export function SignInWithPrivateHarborButton(
  props: SignInWithPrivateHarborButtonProps,
): React.ReactElement {
  const { href, variant = "light", size = "full", disabled = false, ariaLabel = DEFAULT_LABEL } = props;
  const { width, iconTranslateX } = SIZE_DIMENSIONS[size];

  const handleClick = (event: React.MouseEvent<HTMLAnchorElement>): void => {
    if (disabled) {
      event.preventDefault();
    }
  };

  return (
    <a
      className={`phb-button phb-button--${variant} phb-button--${size}`}
      href={href}
      aria-label={ariaLabel}
      aria-disabled={disabled ? "true" : undefined}
      tabIndex={disabled ? -1 : undefined}
      onClick={handleClick}
    >
      <svg
        xmlns="http://www.w3.org/2000/svg"
        width={width}
        height={HEIGHT}
        viewBox={`0 0 ${width} ${HEIGHT}`}
        role="img"
        aria-label={ariaLabel}
        aria-disabled={disabled ? "true" : undefined}
        focusable="false"
        className="phb-btn"
      >
        <title>{ariaLabel}</title>
        <style>{VARIANT_STYLE[variant]}</style>
        <rect className="phb-btn-bg" x={0.5} y={0.5} width={width - 1} height={HEIGHT - 1} rx={8} ry={8} />
        <rect className="phb-btn-ring" x={3} y={3} width={width - 6} height={HEIGHT - 6} rx={5} ry={5} />
        <g className="phb-btn-icon" transform={`translate(${iconTranslateX},10)`}>
          <rect x={2} y={8} width={3} height={8} />
          <rect x={8.5} y={4} width={3} height={12} />
          <rect x={15} y={10} width={3} height={6} />
          <rect x={1} y={16} width={18} height={2} rx={1} ry={1} />
        </g>
        {size === "full" && (
          <text className="phb-btn-label" x={46} y={20} dominantBaseline="middle">
            {DEFAULT_LABEL}
          </text>
        )}
      </svg>
    </a>
  );
}
