// Package web embeds the server-rendered dashboard and public signup templates.
package web

import (
	"embed"
	"html/template"
)

// TemplatesFS holds the embedded dashboard and public signup HTML templates.
//
//go:embed templates/*.html
var TemplatesFS embed.FS

// ParseDashboardTemplates parses all embedded templates (dashboard and public
// signup views) from the embedded FS and returns a *template.Template ready
// to pass to bff.NewDashboardHandler and bff.NewSignupHandler. The name is a
// historical artifact of the dashboard shipping first; it parses the whole
// templates/*.html glob, not just dashboard views.
func ParseDashboardTemplates() (*template.Template, error) {
	return template.ParseFS(TemplatesFS, "templates/*.html")
}
