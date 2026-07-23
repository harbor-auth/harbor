// Package web embeds the server-rendered dashboard templates.
package web

import (
	"embed"
	"html/template"
)

// TemplatesFS holds the embedded dashboard HTML templates.
//
//go:embed templates/*.html
var TemplatesFS embed.FS

// ParseDashboardTemplates parses all dashboard templates from the embedded FS
// and returns a *template.Template ready to pass to bff.NewDashboardHandler.
func ParseDashboardTemplates() (*template.Template, error) {
	return template.ParseFS(TemplatesFS, "templates/*.html")
}
