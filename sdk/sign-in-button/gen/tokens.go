// SPDX-License-Identifier: Apache-2.0

// Package main is the deterministic SVG asset generator for the "Sign in
// with Private Harbor" button + brand kit. tokens.go defines the design
// tokens (colors, geometry, wording, per-state style deltas); generate.go
// renders them to sdk/sign-in-button/assets/ via text/template. Run:
//
//	go run ./sdk/sign-in-button/gen
//
// from the repository root to regenerate the committed assets.
package main

// ButtonLabel is the exact, required wording for every button variant
// (spec REQ-001).
const ButtonLabel = "Sign in with Private Harbor"

// LogomarkName is the accessible name for the standalone logomark asset.
const LogomarkName = "Private Harbor"

// Scheme identifies a button color scheme.
type Scheme string

const (
	SchemeLight   Scheme = "light"
	SchemeDark    Scheme = "dark"
	SchemeNeutral Scheme = "neutral"
)

// Size identifies a button size.
type Size string

const (
	SizeCompact Size = "compact"
	SizeFull    Size = "full"
)

// Variant identifies one button rendering: a color scheme x size pairing.
type Variant struct {
	Scheme Scheme
	Size   Size
}

// Variants enumerates every (scheme x size) combination the generator
// produces, in a fixed order so file emission is deterministic.
var Variants = []Variant{
	{Scheme: SchemeLight, Size: SizeCompact},
	{Scheme: SchemeLight, Size: SizeFull},
	{Scheme: SchemeDark, Size: SizeCompact},
	{Scheme: SchemeDark, Size: SizeFull},
	{Scheme: SchemeNeutral, Size: SizeCompact},
	{Scheme: SchemeNeutral, Size: SizeFull},
}

// CornerRadius is the button's fixed corner radius, in SVG user units (px),
// shared by every scheme and size.
const CornerRadius = 8.0

// MinHeightPx is the minimum rendered height (px) for any button variant.
// See docs/BRAND-GUIDELINES.md for the full minimum-size/clear-space rule.
const MinHeightPx = 40.0

// StrokeWidth is the fixed border stroke width (px) used by the default,
// hover, and disabled states.
const StrokeWidth = 1.0

// FocusRingInset is the gap (px) between the button's outer edge and its
// focus-visible ring, kept inside the button bounds so the ring is never
// clipped by the SVG viewBox.
const FocusRingInset = 3.0

// SizeGeometry describes the fixed pixel geometry for one Size.
type SizeGeometry struct {
	Width     float64
	Height    float64
	PaddingX  float64
	Gap       float64
	IconSize  float64
	FontSize  float64
	ShowLabel bool
}

// Geometry maps each Size to its SizeGeometry. Compact is a fixed-size,
// icon-only square (the minimum-size variant); Full is a fixed-width
// icon+label button.
var Geometry = map[Size]SizeGeometry{
	SizeCompact: {Width: 40, Height: MinHeightPx, PaddingX: 10, Gap: 0, IconSize: 20, FontSize: 14, ShowLabel: false},
	SizeFull:    {Width: 240, Height: MinHeightPx, PaddingX: 16, Gap: 10, IconSize: 20, FontSize: 14, ShowLabel: true},
}

// StateStyle is the fill/stroke/text color for one interactive state.
type StateStyle struct {
	Background string
	Border     string
	Text       string
}

// SchemePalette is the full default/hover/disabled palette plus focus-ring
// color for one Scheme.
//
// Every Background/Text pair meets WCAG 2.1 AA contrast (>=4.5:1 for
// normal-size text, SC 1.4.3); FocusRing meets the >=3:1 non-text contrast
// ratio against Default.Background (SC 1.4.11). Contrast ratios (WCAG 2.1
// relative-luminance formula, verified at generation time):
//
//	light   default text #16181D / bg #FFFFFF  = 17.76:1
//	light   hover   text #16181D / bg #F0F2F5  = 15.83:1
//	light   focus ring #1857C4  / bg #FFFFFF   =  6.56:1
//	dark    default text #FFFFFF / bg #14161C  = 18.08:1
//	dark    hover   text #FFFFFF / bg #1E212A  = 16.08:1
//	dark    focus ring #7EB2FF  / bg #14161C   =  8.35:1
//	neutral default text #FFFFFF / bg #0B4F8A  =  8.40:1
//	neutral hover   text #FFFFFF / bg #0A4576  =  9.88:1
//	neutral focus ring #FFFFFF  / bg #0B4F8A   =  8.40:1
//
// Disabled states are exempt from WCAG contrast requirements (disabled
// controls are excluded from SC 1.4.3/1.4.11) but are kept legibly muted.
type SchemePalette struct {
	Default        StateStyle
	Hover          StateStyle
	Disabled       StateStyle
	FocusRing      string
	FocusRingWidth float64
}

// Palettes maps each Scheme to its SchemePalette.
var Palettes = map[Scheme]SchemePalette{
	SchemeLight: {
		Default:        StateStyle{Background: "#FFFFFF", Border: "#D6D9DE", Text: "#16181D"},
		Hover:          StateStyle{Background: "#F0F2F5", Border: "#C3C8D1", Text: "#16181D"},
		Disabled:       StateStyle{Background: "#F5F6F8", Border: "#E4E7EB", Text: "#9AA1AC"},
		FocusRing:      "#1857C4",
		FocusRingWidth: 2,
	},
	SchemeDark: {
		Default:        StateStyle{Background: "#14161C", Border: "#3A3E47", Text: "#FFFFFF"},
		Hover:          StateStyle{Background: "#1E212A", Border: "#4B4F5A", Text: "#FFFFFF"},
		Disabled:       StateStyle{Background: "#1B1D24", Border: "#2A2D35", Text: "#6B6F79"},
		FocusRing:      "#7EB2FF",
		FocusRingWidth: 2,
	},
	SchemeNeutral: {
		Default:        StateStyle{Background: "#0B4F8A", Border: "#0B4F8A", Text: "#FFFFFF"},
		Hover:          StateStyle{Background: "#0A4576", Border: "#0A4576", Text: "#FFFFFF"},
		Disabled:       StateStyle{Background: "#8FA9BD", Border: "#8FA9BD", Text: "#E8EEF3"},
		FocusRing:      "#FFFFFF",
		FocusRingWidth: 2,
	},
}

// LogomarkColor is the fixed brand color used by the standalone logomark
// asset (assets/logomark.svg), which is not scheme-dependent.
const LogomarkColor = "#0B4F8A"
