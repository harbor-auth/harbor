# Brand guidelines

Rules for using the "Sign in with Private Harbor" button and logomark
correctly, and for what any integration built on this kit may and may not
say about privacy or compliance. Both halves are normative: the size/space
rules in [Minimum size and clear space](#minimum-size-and-clear-space) and
[Prohibited alterations](#prohibited-alterations) apply to every asset under
`assets/`; the [Privacy language](#privacy-language) rules apply to any
copy — in this repo or in a consuming site — that describes what "Sign in
with Private Harbor" does for a user's privacy.

## Minimum size and clear space

**Minimum rendered height: 40px**, for every button variant
(`{light,dark,neutral} × {compact,full}`). This is not a suggestion — it is
the `MinHeightPx` constant the generator in
[`gen/tokens.go`](../gen/tokens.go) uses to produce every asset in
`assets/`, so every vendored SVG and every CSS class in
[`css/sign-in-button.css`](../css/sign-in-button.css) is already built at
this floor. Do not scale a button below 40px rendered height in any layout;
below that height the label and focus ring lose legibility and the target
falls under common touch-target minimums.

**Minimum standalone logomark size: 20×20px.** The logomark
([`assets/logomark.svg`](../assets/logomark.svg)) has a `0 0 20 20`
viewBox and is the same icon rendered inside every button variant at
`IconSize: 20` ([`gen/tokens.go`](../gen/tokens.go)). Used on its own
(outside a button), it must not be rendered smaller than 20×20px.

**Minimum clear space: 25% of the mark's rendered height, on all sides.**
For a button, "the mark" is the whole button (label included, since the
label is baked into the asset, not overlaid); for the standalone logomark,
it's the icon itself. Concretely:

- At the 40px minimum button height, clear space is **≥10px** on every
  side.
- At the 20px minimum logomark height, clear space is **≥5px** on every
  side.
- At any larger rendered size, scale the 25% proportionally — clear space
  must never fall below one quarter of whatever height the mark is
  currently rendered at.

Clear space is measured from the outer edge of the button/logomark to any
other graphic element, text, page edge, or competing call-to-action —
nothing else may sit inside that margin. Padding supplied by a surrounding
layout (a card, a modal) counts toward clear space only if it meets the
25% figure on its own; don't rely on incidental whitespace that happens to
be smaller.

## Prohibited alterations

The assets in `assets/` are generated deterministically from
[`gen/tokens.go`](../gen/tokens.go) precisely so that every rendering of
the mark is byte-identical and predictable
([`gen/determinism_test.go`](../gen/determinism_test.go) enforces this in
CI). Do not:

- **Recolor outside the defined tokens.** Only the `light`, `dark`, and
  `neutral` color schemes in `gen/tokens.go`'s `Palettes` map (and their
  built-in default/hover/disabled states) are permitted. Do not recolor the
  logomark, background, border, or text to match a page theme, brand
  palette, or dark-mode variant that isn't one of the three shipped
  schemes — pick whichever of `light`/`dark`/`neutral` has sufficient
  contrast against your background instead.
- **Distort the mark.** No non-uniform (stretch/squash) scaling of the
  button or logomark. Uniform scaling that respects the minimum sizes above
  is fine; changing the aspect ratio is not.
- **Rotate the mark.** The button and logomark must always be rendered
  upright, at 0°.
- **Add effects.** No drop shadows, glows, gradients, outlines, opacity
  changes (outside the shipped `disabled` state), filters, or any other
  visual treatment not already present in the generated SVG. The assets
  already define their own default/hover/focus/disabled states
  ([`SECURITY.md`](SECURITY.md) and [`css/sign-in-button.css`](../css/sign-in-button.css));
  adding your own interaction styling on top produces a mark that no
  longer matches what ships from this kit.

If a layout genuinely doesn't fit any shipped variant, that's a signal to
request a new variant be added upstream — not to hand-modify a generated
asset.

## Prohibited implications

- **Must not imply Harbor endorses the integrating site.** Using the "Sign
  in with Private Harbor" button means Harbor authenticates users for your
  site; it does not mean Harbor reviews, vouches for, or endorses your
  site's content, business, or practices. Copy near the button (or
  elsewhere on the integrating site) must not state or imply Harbor
  endorsement, partnership, or approval beyond "this site supports signing
  in with a Private Harbor account."
- **Must not imply the integrating site itself is privacy-certified.**
  Offering "Sign in with Private Harbor" describes how a user authenticates
  — it says nothing about how the *rest* of the integrating site handles
  data afterward. Don't caption the button (or otherwise present it) in a
  way that implies the RP itself has been privacy-audited, certified, or
  endorsed as compliant with any regulation or standard because it uses
  this button. Any such claim about the RP's own practices must stand on
  its own evidence, entirely separate from this kit.

## Privacy language

Every privacy or compliance statement made about "Sign in with Private
Harbor" — in this kit's own docs, in a consuming site's marketing copy, or
in support material — must do one of two things:

1. **Link to a verifiable artifact already in this repository**, most
   commonly [`docs/design/product/privacy-positioning.md`](../../../docs/design/product/privacy-positioning.md)
   (the Google/Apple/Harbor positioning and comparison tables) or
   [`docs/design/protocol/ppid-guarantees.md`](../../../docs/design/protocol/ppid-guarantees.md)
   (the tiered PPID unlinkability guarantees, §3.2.7), so a reader can go
   verify the claim against source code, test vectors, or the honest
   strength/verification-method table those docs provide; **or**
2. **Be phrased as a design property, not a certification.** State what the
   system is architecturally built to do ("Harbor issues a different
   pairwise `sub` per relying party, so two RPs comparing subject
   identifiers cannot join them to the same user — see
   [`ppid-guarantees.md` §3.2.7, Tier 1](../../../docs/design/protocol/ppid-guarantees.md#3-2-7-honest-summary-three-tier-privacy-guarantee),
   independently verifiable from source"), never as an achieved
   third-party attestation the reader can't check.

Two worked examples, contrasting a claim this kit's own docs already make
correctly against the same claim written the wrong way:

| Don't write | Do write instead |
|---|---|
| "Private Harbor is GDPR certified." | "Harbor's self-serve dashboard lets a user see and revoke every RP they've connected — see [`ppid-guarantees.md` §3.2.4](../../../docs/design/protocol/ppid-guarantees.md#3-2-4-why-even-harbor-struggles-to-correlate-users-across-rps) for how the underlying reverse-index is access-controlled and audited." |
| "Sign in with Private Harbor is more private than Google or Apple sign-in, full stop." | "See [`privacy-positioning.md`](../../../docs/design/product/privacy-positioning.md) for the specific, evidenced dimensions (per-RP PPID vs. Apple's per-developer-team `sub`, data sovereignty, open-source auditability) Harbor's approach differs on — and where the comparison is a genuine trade-off, not a strict win." |

**Explicitly forbidden, anywhere in this kit or in copy describing it,**
regardless of phrasing or qualifier: unqualified certification or
compliance claims such as "GDPR certified," "SOC 2 certified," "SOC 2
compliant," "HIPAA compliant," "ISO 27001 certified," or any equivalent
claim of third-party attestation that isn't backed by a link to an actual
certificate, audit report, or other verifiable artifact. Harbor's honest
position — stated plainly in
[`ppid-guarantees.md` §3.2.7](../../../docs/design/protocol/ppid-guarantees.md#3-2-7-honest-summary-three-tier-privacy-guarantee) —
is that its strongest privacy guarantee (per-RP unlinkability) is
verifiable by construction from source code, its operator-correlation
constraint is "strong, but trust-the-operator until reproducible builds +
transparency log ship," and its log-minimization commitment is "policy +
design convention... not cryptographically enforced." None of that is a
certification, and nothing in this kit — or in copy describing it — may
claim otherwise. If Harbor obtains a genuine third-party certification in
the future, the claim belongs in `privacy-positioning.md` with a link to
the actual attestation, not asserted bare in integration collateral.
