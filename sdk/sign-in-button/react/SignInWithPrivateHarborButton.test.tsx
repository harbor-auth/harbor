// SPDX-License-Identifier: Apache-2.0

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import {
  SignInWithPrivateHarborButton,
  type SignInWithPrivateHarborButtonProps,
  type SignInWithPrivateHarborButtonSize,
  type SignInWithPrivateHarborButtonVariant,
} from "./SignInWithPrivateHarborButton";

const DEFAULT_NAME = "Sign in with Private Harbor";

const VARIANTS: SignInWithPrivateHarborButtonVariant[] = ["light", "dark", "neutral"];
const SIZES: SignInWithPrivateHarborButtonSize[] = ["compact", "full"];
const DISABLED_STATES = [false, true];

describe("SignInWithPrivateHarborButton", () => {
  for (const variant of VARIANTS) {
    for (const size of SIZES) {
      for (const disabled of DISABLED_STATES) {
        it(`variant=${variant} size=${size} disabled=${disabled}: accessible name is "${DEFAULT_NAME}"`, () => {
          render(
            <SignInWithPrivateHarborButton href="/auth/login" variant={variant} size={size} disabled={disabled} />,
          );

          const link = screen.getByRole("link", { name: DEFAULT_NAME });
          expect(link).toHaveAttribute("href", "/auth/login");
          if (disabled) {
            expect(link).toHaveAttribute("aria-disabled", "true");
          } else {
            expect(link).not.toHaveAttribute("aria-disabled");
          }
        });
      }
    }
  }

  it("honors an ariaLabel override as the accessible name, for every variant/size/disabled combination", () => {
    for (const variant of VARIANTS) {
      for (const size of SIZES) {
        for (const disabled of DISABLED_STATES) {
          const overrideLabel = `Continue with Private Harbor (${variant}/${size}/${disabled})`;
          const { unmount } = render(
            <SignInWithPrivateHarborButton
              href="/auth/login"
              variant={variant}
              size={size}
              disabled={disabled}
              ariaLabel={overrideLabel}
            />,
          );

          expect(screen.getByRole("link", { name: overrideLabel })).toBeInTheDocument();
          expect(screen.queryByRole("link", { name: DEFAULT_NAME })).not.toBeInTheDocument();

          unmount();
        }
      }
    }
  });

  it("defaults to variant=light and size=full when omitted", () => {
    render(<SignInWithPrivateHarborButton href="/auth/login" />);
    const link = screen.getByRole("link", { name: DEFAULT_NAME });
    expect(link.className).toContain("phb-button--light");
    expect(link.className).toContain("phb-button--full");
  });

  // REQ-002 / the button's core security property: the props type must not
  // let an integrator hand it OIDC flow parameters. If it did, a caller
  // could construct a hand-built /authorize link from the outside, exactly
  // the anti-pattern docs/SECURITY.md forbids (see also
  // examples/minimal-rp/security_test.go, which proves the same property
  // on the RP side of the flow).
  const FORBIDDEN_PROP_NAMES = [
    "state",
    "nonce",
    "codeChallenge",
    "code_challenge",
    "codeVerifier",
    "code_verifier",
    "codeChallengeMethod",
    "code_challenge_method",
    "clientId",
    "client_id",
    "redirectUri",
    "redirect_uri",
    "scope",
    "authorizeUrl",
    "authorizationEndpoint",
  ];

  it("has no state/nonce/PKCE (or other OIDC flow parameter) fields in its props type", () => {
    // Runtime witness: every prop this component actually accepts, driven
    // through a real render so this fails if the component reads a
    // forbidden prop off `props` even without it being declared in the
    // TypeScript type (a plain JS/any consumer could still pass one).
    const probeProps = {
      href: "/auth/login",
      variant: "light",
      size: "full",
      disabled: false,
      ariaLabel: DEFAULT_NAME,
      // Forbidden flow parameters a malicious/careless integrator might
      // try to smuggle in — none of these may appear on the rendered
      // output the component controls (the anchor's own attributes),
      // proving the component neither declares nor consumes them.
      state: "attacker-state",
      nonce: "attacker-nonce",
      codeChallenge: "attacker-challenge",
      code_challenge: "attacker-challenge",
      clientId: "attacker-client",
      redirectUri: "https://evil.example.com",
    } as unknown as SignInWithPrivateHarborButtonProps;

    const { container } = render(<SignInWithPrivateHarborButton {...probeProps} />);
    const html = container.innerHTML;
    for (const forbidden of ["attacker-state", "attacker-nonce", "attacker-challenge", "attacker-client", "evil.example.com"]) {
      expect(html).not.toContain(forbidden);
    }

    // Static witness: parse the component's own prop type declaration and
    // assert none of its declared field names is one of the forbidden
    // OIDC flow parameters. This is a runtime (not just tsc-time) check:
    // it reads and scans the actual shipped source, so it fails the
    // moment someone adds e.g. `state?: string;` to the interface, without
    // requiring a separate typecheck step.
    const here = path.dirname(fileURLToPath(import.meta.url));
    const source = fs.readFileSync(path.join(here, "SignInWithPrivateHarborButton.tsx"), "utf8");

    const interfaceMatch = source.match(
      /export interface SignInWithPrivateHarborButtonProps\s*\{([\s\S]*?)\n\}/,
    );
    expect(interfaceMatch, "SignInWithPrivateHarborButtonProps interface not found in source").not.toBeNull();
    const interfaceBody = interfaceMatch![1];

    const declaredFieldNames = Array.from(
      interfaceBody.matchAll(/^\s*([A-Za-z_$][\w$]*)\??:/gm),
      (m: RegExpMatchArray) => m[1],
    );
    expect(declaredFieldNames.length).toBeGreaterThan(0);

    for (const forbidden of FORBIDDEN_PROP_NAMES) {
      expect(
        declaredFieldNames,
        `SignInWithPrivateHarborButtonProps must not declare a "${forbidden}" field`,
      ).not.toContain(forbidden);
    }
  });
});

// Compile-time witness, checked by `npm run typecheck` (tsc --noEmit): the
// props type structurally has no forbidden OIDC flow-parameter keys. If a
// forbidden key is ever added to SignInWithPrivateHarborButtonProps, this
// line stops compiling because AssertNever below resolves to `false`,
// which is not assignable to `true`.
type ForbiddenPropKey =
  | "state"
  | "nonce"
  | "codeChallenge"
  | "code_challenge"
  | "codeVerifier"
  | "code_verifier"
  | "codeChallengeMethod"
  | "code_challenge_method"
  | "clientId"
  | "client_id"
  | "redirectUri"
  | "redirect_uri";
type AssertNever<T> = [T] extends [never] ? true : false;
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const _assertNoForbiddenPropKeys: AssertNever<
  Extract<keyof SignInWithPrivateHarborButtonProps, ForbiddenPropKey>
> = true;
