// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"text/template"
)

// num formats f deterministically (shortest round-trippable decimal, no
// locale/platform variance) for embedding in generated SVG attributes.
func num(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// iconBar is one bar of the fixed "masts over water" logomark glyph, in a
// 0..20 square coordinate space. Rendered with fill="currentColor" in the
// button asset and a fixed brand color in the standalone logomark.
type iconBar struct {
	X, Y, Width, Height float64
}

// iconBars is the ordered, fixed set of logomark bars — a slice (not a
// map), so iteration order is deterministic.
var iconBars = []iconBar{
	{X: 2, Y: 8, Width: 3, Height: 8},
	{X: 8.5, Y: 4, Width: 3, Height: 12},
	{X: 15, Y: 10, Width: 3, Height: 6},
}

const (
	iconViewBox         = 20.0
	iconWaterlineX      = 1.0
	iconWaterlineY      = 16.0
	iconWaterlineWidth  = 18.0
	iconWaterlineHeight = 2.0
	iconWaterlineRadius = 1.0
)

type iconBarView struct {
	X, Y, Width, Height string
}

func renderIconBars() []iconBarView {
	views := make([]iconBarView, len(iconBars))
	for i, b := range iconBars {
		views[i] = iconBarView{X: num(b.X), Y: num(b.Y), Width: num(b.Width), Height: num(b.Height)}
	}
	return views
}

// buttonView holds the pre-formatted (string) values consumed by
// buttonSVGTemplate. All numeric formatting happens in Go (via num), not in
// the template, so the template is pure substitution.
type buttonView struct {
	ClassName string
	AriaLabel string
	Label     string
	ShowLabel bool

	Width, Height         string
	Radius                string
	StrokeWidth           string
	StrokeHalf            string
	InnerWidth            string
	InnerHeight           string
	Background            string
	Border                string
	HoverBackground       string
	HoverBorder           string
	DisabledBackground    string
	DisabledBorder        string
	Text                  string
	DisabledText          string
	FocusRing             string
	FocusRingWidth        string
	RingX, RingY          string
	RingWidth, RingHeight string
	RingRadius            string
	FontSize              string
	LabelX, LabelY        string
	IconX, IconY          string
	IconBars              []iconBarView
	WaterlineX            string
	WaterlineY            string
	WaterlineWidth        string
	WaterlineHeight       string
	WaterlineRadius       string
}

const buttonSVGTemplateSrc = `<?xml version="1.0" encoding="UTF-8"?>
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- GENERATED FILE. DO NOT EDIT.
     Source: sdk/sign-in-button/gen (tokens.go, generate.go). Regenerate
     with ` + "`go run ./sdk/sign-in-button/gen`" + ` from the repository root. -->
<svg xmlns="http://www.w3.org/2000/svg" width="{{.Width}}" height="{{.Height}}" viewBox="0 0 {{.Width}} {{.Height}}" role="img" aria-label="{{.AriaLabel}}" focusable="false" class="{{.ClassName}}">
<title>{{.AriaLabel}}</title>
<style>
.{{.ClassName}}-bg{fill:{{.Background}};stroke:{{.Border}};stroke-width:{{.StrokeWidth}};}
.{{.ClassName}}-ring{fill:none;stroke:transparent;stroke-width:{{.FocusRingWidth}};}
.{{.ClassName}}-label,.{{.ClassName}}-icon{fill:{{.Text}};font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;}
.{{.ClassName}}-label{font-size:{{.FontSize}}px;font-weight:600;}
.{{.ClassName}}:hover .{{.ClassName}}-bg{fill:{{.HoverBackground}};stroke:{{.HoverBorder}};}
.{{.ClassName}}:focus-visible .{{.ClassName}}-ring{stroke:{{.FocusRing}};}
.{{.ClassName}}.{{.ClassName}}--disabled .{{.ClassName}}-bg,.{{.ClassName}}[aria-disabled="true"] .{{.ClassName}}-bg{fill:{{.DisabledBackground}};stroke:{{.DisabledBorder}};}
.{{.ClassName}}.{{.ClassName}}--disabled .{{.ClassName}}-label,.{{.ClassName}}.{{.ClassName}}--disabled .{{.ClassName}}-icon,.{{.ClassName}}[aria-disabled="true"] .{{.ClassName}}-label,.{{.ClassName}}[aria-disabled="true"] .{{.ClassName}}-icon{fill:{{.DisabledText}};}
</style>
<rect class="{{.ClassName}}-bg" x="{{.StrokeHalf}}" y="{{.StrokeHalf}}" width="{{.InnerWidth}}" height="{{.InnerHeight}}" rx="{{.Radius}}" ry="{{.Radius}}"/>
<rect class="{{.ClassName}}-ring" x="{{.RingX}}" y="{{.RingY}}" width="{{.RingWidth}}" height="{{.RingHeight}}" rx="{{.RingRadius}}" ry="{{.RingRadius}}"/>
<g class="{{.ClassName}}-icon" transform="translate({{.IconX}},{{.IconY}})">
{{range .IconBars}}<rect x="{{.X}}" y="{{.Y}}" width="{{.Width}}" height="{{.Height}}"/>
{{end}}<rect x="{{$.WaterlineX}}" y="{{$.WaterlineY}}" width="{{$.WaterlineWidth}}" height="{{$.WaterlineHeight}}" rx="{{$.WaterlineRadius}}" ry="{{$.WaterlineRadius}}"/>
</g>
{{if .ShowLabel}}<text class="{{.ClassName}}-label" x="{{.LabelX}}" y="{{.LabelY}}" dominant-baseline="middle">{{.Label}}</text>
{{end}}</svg>
`

var buttonSVGTemplate = template.Must(template.New("button").Parse(buttonSVGTemplateSrc))

type logomarkView struct {
	Size            string
	ViewBox         string
	AriaLabel       string
	Color           string
	IconBars        []iconBarView
	WaterlineX      string
	WaterlineY      string
	WaterlineWidth  string
	WaterlineHeight string
	WaterlineRadius string
}

const logomarkSVGTemplateSrc = `<?xml version="1.0" encoding="UTF-8"?>
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- GENERATED FILE. DO NOT EDIT.
     Source: sdk/sign-in-button/gen (tokens.go, generate.go). Regenerate
     with ` + "`go run ./sdk/sign-in-button/gen`" + ` from the repository root. -->
<svg xmlns="http://www.w3.org/2000/svg" width="{{.Size}}" height="{{.Size}}" viewBox="0 0 {{.ViewBox}} {{.ViewBox}}" role="img" aria-label="{{.AriaLabel}}" focusable="false">
<title>{{.AriaLabel}}</title>
<g fill="{{.Color}}">
{{range .IconBars}}<rect x="{{.X}}" y="{{.Y}}" width="{{.Width}}" height="{{.Height}}"/>
{{end}}<rect x="{{$.WaterlineX}}" y="{{$.WaterlineY}}" width="{{$.WaterlineWidth}}" height="{{$.WaterlineHeight}}" rx="{{$.WaterlineRadius}}" ry="{{$.WaterlineRadius}}"/>
</g>
</svg>
`

var logomarkSVGTemplate = template.Must(template.New("logomark").Parse(logomarkSVGTemplateSrc))

func renderButton(v Variant) ([]byte, error) {
	geo, ok := Geometry[v.Size]
	if !ok {
		return nil, fmt.Errorf("render button %s-%s: unknown size", v.Scheme, v.Size)
	}
	pal, ok := Palettes[v.Scheme]
	if !ok {
		return nil, fmt.Errorf("render button %s-%s: unknown scheme", v.Scheme, v.Size)
	}

	iconX := (geo.Width - geo.IconSize) / 2
	iconY := (geo.Height - geo.IconSize) / 2
	labelX := 0.0
	if geo.ShowLabel {
		iconX = geo.PaddingX
		labelX = geo.PaddingX + geo.IconSize + geo.Gap
	}

	view := buttonView{
		// Scoped by color scheme (not just "phb-btn") so that when multiple
		// variants' generated SVGs are embedded in the same HTML document,
		// their <style> blocks don't declare the same selectors — an
		// unscoped shared class name lets the last <style> block in the
		// document win the cascade for every instance's fill/stroke colors,
		// regardless of that instance's own variant.
		ClassName: fmt.Sprintf("phb-btn-%s", v.Scheme),
		AriaLabel: ButtonLabel,
		Label:     ButtonLabel,
		ShowLabel: geo.ShowLabel,

		Width:              num(geo.Width),
		Height:             num(geo.Height),
		Radius:             num(CornerRadius),
		StrokeWidth:        num(StrokeWidth),
		StrokeHalf:         num(StrokeWidth / 2),
		InnerWidth:         num(geo.Width - StrokeWidth),
		InnerHeight:        num(geo.Height - StrokeWidth),
		Background:         pal.Default.Background,
		Border:             pal.Default.Border,
		HoverBackground:    pal.Hover.Background,
		HoverBorder:        pal.Hover.Border,
		DisabledBackground: pal.Disabled.Background,
		DisabledBorder:     pal.Disabled.Border,
		Text:               pal.Default.Text,
		DisabledText:       pal.Disabled.Text,
		FocusRing:          pal.FocusRing,
		FocusRingWidth:     num(pal.FocusRingWidth),
		RingX:              num(FocusRingInset),
		RingY:              num(FocusRingInset),
		RingWidth:          num(geo.Width - 2*FocusRingInset),
		RingHeight:         num(geo.Height - 2*FocusRingInset),
		RingRadius:         num(CornerRadius - FocusRingInset),
		FontSize:           num(geo.FontSize),
		LabelX:             num(labelX),
		LabelY:             num(geo.Height / 2),
		IconX:              num(iconX),
		IconY:              num(iconY),
		IconBars:           renderIconBars(),
		WaterlineX:         num(iconWaterlineX),
		WaterlineY:         num(iconWaterlineY),
		WaterlineWidth:     num(iconWaterlineWidth),
		WaterlineHeight:    num(iconWaterlineHeight),
		WaterlineRadius:    num(iconWaterlineRadius),
	}

	var buf bytes.Buffer
	if err := buttonSVGTemplate.Execute(&buf, view); err != nil {
		return nil, fmt.Errorf("render button %s-%s: %w", v.Scheme, v.Size, err)
	}
	return buf.Bytes(), nil
}

func renderLogomark() ([]byte, error) {
	view := logomarkView{
		Size:            num(iconViewBox),
		ViewBox:         num(iconViewBox),
		AriaLabel:       LogomarkName,
		Color:           LogomarkColor,
		IconBars:        renderIconBars(),
		WaterlineX:      num(iconWaterlineX),
		WaterlineY:      num(iconWaterlineY),
		WaterlineWidth:  num(iconWaterlineWidth),
		WaterlineHeight: num(iconWaterlineHeight),
		WaterlineRadius: num(iconWaterlineRadius),
	}

	var buf bytes.Buffer
	if err := logomarkSVGTemplate.Execute(&buf, view); err != nil {
		return nil, fmt.Errorf("render logomark: %w", err)
	}
	return buf.Bytes(), nil
}

func buttonFileName(v Variant) string {
	return fmt.Sprintf("button-%s-%s.svg", v.Scheme, v.Size)
}

// Generate renders every asset in Variants, plus the standalone logomark,
// to dir, deterministically (fixed float formatting, stable attribute
// ordering, no timestamps, no random IDs).
func Generate(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("generate: %w", err)
	}

	for _, v := range Variants {
		data, err := renderButton(v)
		if err != nil {
			return fmt.Errorf("generate: %w", err)
		}
		path := filepath.Join(dir, buttonFileName(v))
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return fmt.Errorf("generate: write %s: %w", path, err)
		}
	}

	logomark, err := renderLogomark()
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}
	logomarkPath := filepath.Join(dir, "logomark.svg")
	if err := os.WriteFile(logomarkPath, logomark, 0o644); err != nil {
		return fmt.Errorf("generate: write %s: %w", logomarkPath, err)
	}

	return nil
}

func main() {
	dir := flag.String("dir", "sdk/sign-in-button/assets", "output directory for generated SVG assets")
	flag.Parse()

	if err := Generate(*dir); err != nil {
		fmt.Fprintln(os.Stderr, "generate:", err)
		os.Exit(1)
	}
}
