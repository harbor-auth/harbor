package oidcapi

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/harbor-auth/harbor/web"
)

var consentPage = template.Must(template.ParseFS(web.TemplatesFS, "templates/consent.html"))

type consentPageData struct {
	RequestID, AppHost string
	Permissions        []string
}

func (s *Server) renderConsentPage(w http.ResponseWriter, r *http.Request, requestID string) {
	if s.bffSessions == nil {
		writeAuthorizeErrorPage(w)
		return
	}
	session, err := s.bffSessions.Get(r.Context(), requestID)
	if err != nil || !session.ConsentPending || session.UserID == "" || !validSessionNonce(r, session) {
		writeAuthorizeErrorPage(w)
		return
	}
	destination, err := url.Parse(session.RedirectURI)
	if err != nil || destination.Hostname() == "" {
		writeAuthorizeErrorPage(w)
		return
	}
	labels := map[string]string{"openid": "Your account ID for this app", "email": "Your private relay email address", "profile": "Basic profile information", "offline_access": "Keep you signed in when you return"}
	data := consentPageData{RequestID: requestID, AppHost: destination.Hostname()}
	for _, scope := range strings.Fields(session.Scope) {
		label, ok := labels[scope]
		if !ok {
			label = scope
		}
		data.Permissions = append(data.Permissions, label)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := consentPage.ExecuteTemplate(w, "consent.html", data); err != nil {
		http.Error(w, "could not display consent", http.StatusInternalServerError)
	}
}
