package bff

import (
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/harbor-auth/harbor/internal/clients"
	"github.com/harbor-auth/harbor/internal/mgmtapi"
	"github.com/harbor-auth/harbor/internal/oidc"
	"github.com/harbor-auth/harbor/internal/telemetry"
)

// DashboardConsentStore is the narrow consent interface the dashboard needs.
// Reuses the mgmtapi definition (satisfied by clients.DBConsentStore).
type DashboardConsentStore interface {
	List(ctx context.Context, userID string) ([]oidc.ConsentGrant, error)
	Get(ctx context.Context, userID, clientID string) (oidc.ConsentGrant, bool, error)
	Revoke(ctx context.Context, id string) error
}

// DashboardSessionStore is the narrow session interface the dashboard needs
// for the Sessions & Devices view and the revocation cascade. Satisfied by
// clients.DBSessionStore.
type DashboardSessionStore interface {
	ListSessionsByUser(ctx context.Context, userID string) ([]oidc.RefreshSession, error)
	RevokeSession(ctx context.Context, id string) error
	RevokeSessionsByUserClient(ctx context.Context, userID, clientID string) error
}

// DashboardRelayStore is the narrow relay interface the dashboard needs for
// the per-RP email-relay toggle. Satisfied by relay.Store when email-relay-service
// is deployed; nil when it is not (soft toggle — graceful absence).
type DashboardRelayStore interface {
	ListByUser(ctx context.Context, userID string) ([]DashboardRelayAddress, error)
	Deactivate(ctx context.Context, addressID string) error
}

// DashboardRelayAddress is a dashboard-facing summary of a relay address.
type DashboardRelayAddress struct {
	ID       string
	Token    string
	ClientID string
	State    string
	Region   string
}

// DashboardHandler serves the user privacy dashboard. It composes shipped
// primitives (consent-ledger, user-audit-trail, session + credential stores)
// and renders server-side HTML via html/template for XSS-safe output.
//
// All handlers:
//   - read caller identity from bff.UserIDFromContext (set by the BFF session middleware)
//   - are gated by bff.RequireFullScope (must be wired by the caller on registration)
//   - are strictly caller-scoped — no cross-user reads
//   - are region-pinned (inheriting the Gate-1 guardrail from the BFF session)
type DashboardHandler struct {
	consents    DashboardConsentStore
	sessions    DashboardSessionStore
	credentials clients.DashboardCredentialStore
	auditTrail  *mgmtapi.AuditTrailDeps
	relay       DashboardRelayStore // nil when email-relay-service is not deployed

	// aggregate-only Prometheus counters — no PII in labels (INV §5)
	pageViews      *telemetry.Counter
	appRevokes     *telemetry.Counter
	sessionRevokes *telemetry.Counter

	tmpl   *template.Template
	logger *slog.Logger
}

// NewDashboardHandler returns a handler ready to serve the privacy dashboard.
// tmpl must be a parsed *html/template.Template containing named templates for
// each view (see web/templates/). A nil relay is valid — the relay toggle will
// be absent from the rendered dashboard (soft dependency).
func NewDashboardHandler(
	consents DashboardConsentStore,
	sessions DashboardSessionStore,
	credentials clients.DashboardCredentialStore,
	audit *mgmtapi.AuditTrailDeps,
	relay DashboardRelayStore,
	tmpl *template.Template,
	logger *slog.Logger,
) *DashboardHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &DashboardHandler{
		consents:    consents,
		sessions:    sessions,
		credentials: credentials,
		auditTrail:  audit,
		relay:       relay,
		tmpl:        tmpl,
		logger:      logger,
		// Aggregate-only counters: partitioned by endpoint (page views) or outcome
		// (mutations). No user / IP / session dimension — no PII (INVARIANT §5).
		pageViews:      telemetry.NewCounter("dashboard_page_views_total", "Total dashboard page views by view.", telemetry.DimEndpoint),
		appRevokes:     telemetry.NewCounter("dashboard_app_revokes_total", "Total app consent revocations from the dashboard.", telemetry.DimOutcome),
		sessionRevokes: telemetry.NewCounter("dashboard_session_revokes_total", "Total session revocations from the dashboard.", telemetry.DimOutcome),
	}
}

// Routes registers the dashboard routes on mux behind RequireFullScope.
// All routes require the BFF session middleware to be active upstream.
func (h *DashboardHandler) Routes(mux *http.ServeMux) {
	wrap := func(handler http.Handler) http.Handler {
		return RequireFullScope(handler)
	}
	mux.Handle("GET /dashboard", wrap(http.HandlerFunc(h.GetDashboard)))
	mux.Handle("GET /dashboard/apps", wrap(http.HandlerFunc(h.GetConnectedApps)))
	mux.Handle("POST /dashboard/apps/{grant_id}/revoke", wrap(http.HandlerFunc(h.PostRevokeApp)))
	mux.Handle("GET /dashboard/activity", wrap(http.HandlerFunc(h.GetActivity)))
	mux.Handle("GET /dashboard/sessions", wrap(http.HandlerFunc(h.GetSessions)))
	mux.Handle("POST /dashboard/sessions/{session_id}/revoke", wrap(http.HandlerFunc(h.PostRevokeSession)))
	mux.Handle("POST /dashboard/credentials/{credential_id}/revoke", wrap(http.HandlerFunc(h.PostRevokeCredential)))
	mux.Handle("GET /dashboard/relay", wrap(http.HandlerFunc(h.GetRelayToggles)))
	mux.Handle("POST /dashboard/relay/{address_id}/deactivate", wrap(http.HandlerFunc(h.PostDeactivateRelay)))
}

// --- view data types (passed to html/template; all user-supplied strings are
// rendered via {{.Field}} so html/template applies contextual escaping) ---

// dashboardAppsData is the template data for the Connected Apps view.
type dashboardAppsData struct {
	Grants []oidc.ConsentGrant
}

// dashboardActivityData is the template data for the Activity view.
type dashboardActivityData struct {
	Events []dashboardAuditEvent
}

type dashboardAuditEvent struct {
	ID         string
	EventType  string
	ClientID   string // empty when nil
	OccurredAt time.Time
	Detail     string // decrypted JSON detail, empty when unavailable
}

// dashboardSessionsData is the template data for the Sessions & Devices view.
type dashboardSessionsData struct {
	Sessions    []oidc.RefreshSession
	Credentials []clients.DashboardCredential
}

// dashboardRelayData is the template data for the Email Relay Toggle view.
type dashboardRelayData struct {
	Addresses   []DashboardRelayAddress
	RelayAbsent bool // true when relay is not deployed
}

// --- handler implementations ---

// GetDashboard renders the dashboard overview page (summary of all four sections).
func (h *DashboardHandler) GetDashboard(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	h.pageViews.Inc(telemetry.Endpoint(telemetry.EndpointDashboard))
	h.renderTemplate(w, r, "dashboard.html", map[string]string{"UserID": userID})
}

// GetConnectedApps renders the Connected Apps view: the caller's active consent
// grants (scopes, granted-at, last-used) from the consent-ledger.
func (h *DashboardHandler) GetConnectedApps(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	grants, err := h.consents.List(r.Context(), userID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "bff: dashboard: list consent grants failed",
			"error", err)
		http.Error(w, "failed to load connected apps", http.StatusInternalServerError)
		return
	}
	h.pageViews.Inc(telemetry.Endpoint(telemetry.EndpointConsent))
	h.renderTemplate(w, r, "dashboard_apps.html", dashboardAppsData{Grants: grants})
}

// PostRevokeApp revokes a consent grant by grant_id and cascades revocation to
// active sessions/tokens for that RP (INVARIANT: revocation cascade fails closed).
// The grant must belong to the authenticated caller; cross-user revocation is
// refused at the store level.
func (h *DashboardHandler) PostRevokeApp(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	grantID := r.PathValue("grant_id")
	if grantID == "" {
		http.Error(w, "grant_id is required", http.StatusBadRequest)
		return
	}

	// Derive the clientID from the caller's grant list so we can (a) confirm
	// ownership and (b) obtain the clientID needed for session cascade.
	grants, err := h.consents.List(r.Context(), userID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "bff: dashboard: list grants for revoke failed", "error", err)
		http.Error(w, "failed to revoke app", http.StatusInternalServerError)
		return
	}
	var targetClientID string
	for _, g := range grants {
		if g.ID == grantID {
			targetClientID = g.ClientID
			break
		}
	}
	if targetClientID == "" {
		// Grant not found or doesn't belong to this user — return 404.
		http.Error(w, "grant not found", http.StatusNotFound)
		return
	}

	// Revoke the consent grant.
	if err := h.consents.Revoke(r.Context(), grantID); err != nil {
		h.logger.ErrorContext(r.Context(), "bff: dashboard: consent revoke failed",
			"error", err)
		http.Error(w, "failed to revoke app", http.StatusInternalServerError)
		return
	}

	// Cascade: revoke all sessions for (user, client) — matching the mgmtapi
	// consent-revoke cascade pattern. Fails closed (INVARIANT §3).
	if h.sessions != nil {
		if err := h.sessions.RevokeSessionsByUserClient(r.Context(), userID, targetClientID); err != nil {
			h.logger.ErrorContext(r.Context(), "bff: dashboard: session user-client cascade failed",
				"error", err)
			http.Error(w, "failed to revoke app sessions", http.StatusInternalServerError)
			return
		}
	}

	h.appRevokes.Inc(telemetry.Outcome(telemetry.OutcomeSuccess))
	http.Redirect(w, r, "/dashboard/apps", http.StatusSeeOther)
}

// GetActivity renders the Activity view: the caller's own decrypted audit-trail
// events (login, token issue/refresh/revoke, consent changes). Decryption uses
// the caller's own DEK only — no operator plaintext path (INVARIANT §2).
func (h *DashboardHandler) GetActivity(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	if h.auditTrail == nil {
		// Audit trail not deployed — render empty activity view (graceful absence).
		h.renderTemplate(w, r, "dashboard_activity.html", dashboardActivityData{})
		return
	}

	const defaultLimit = 50
	region, dekWrapped, err := h.auditTrail.Users.LoadUserForAudit(r.Context(), userID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "bff: dashboard: load user for audit failed", "error", err)
		http.Error(w, "failed to load activity", http.StatusInternalServerError)
		return
	}

	dek, err := h.auditTrail.Keys.UnwrapDEK(r.Context(), region, dekWrapped)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "bff: dashboard: DEK unwrap failed", "error", err)
		http.Error(w, "failed to load activity", http.StatusInternalServerError)
		return
	}

	rows, err := h.auditTrail.Store.ListAuditEvents(r.Context(), userID, defaultLimit, 0)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "bff: dashboard: list audit events failed", "error", err)
		http.Error(w, "failed to load activity", http.StatusInternalServerError)
		return
	}

	aad := []byte("harbor-audit-payload-v1:" + userID)
	events := make([]dashboardAuditEvent, 0, len(rows))
	for _, row := range rows {
		ev := dashboardAuditEvent{
			ID:         row.ID,
			EventType:  row.EventType,
			OccurredAt: row.OccurredAt,
		}
		if row.ClientID != nil {
			ev.ClientID = *row.ClientID
		}
		if len(row.PayloadEncrypted) > 0 {
			pt, decErr := h.auditTrail.Decryptor.Decrypt(dek, row.PayloadEncrypted, aad)
			if decErr != nil {
				h.logger.WarnContext(r.Context(), "bff: dashboard: decrypt audit payload failed",
					"event_type", row.EventType, "error", decErr)
			} else {
				ev.Detail = string(pt)
			}
		}
		events = append(events, ev)
	}

	h.pageViews.Inc(telemetry.Endpoint(telemetry.EndpointAudit))
	h.renderTemplate(w, r, "dashboard_activity.html", dashboardActivityData{Events: events})
}

// GetSessions renders the Sessions & Devices view: active sessions and registered
// authenticators (passkeys) for the caller. Both lists are strictly caller-scoped.
func (h *DashboardHandler) GetSessions(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	sessions, err := h.sessions.ListSessionsByUser(r.Context(), userID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "bff: dashboard: list sessions failed", "error", err)
		http.Error(w, "failed to load sessions", http.StatusInternalServerError)
		return
	}

	credentials, err := h.credentials.ListCredentialsByUser(r.Context(), userID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "bff: dashboard: list credentials failed", "error", err)
		http.Error(w, "failed to load devices", http.StatusInternalServerError)
		return
	}

	h.pageViews.Inc(telemetry.Endpoint(telemetry.EndpointSession))
	h.renderTemplate(w, r, "dashboard_sessions.html", dashboardSessionsData{
		Sessions:    sessions,
		Credentials: credentials,
	})
}

// PostRevokeSession revokes a single active session by session_id.
// The session must belong to the authenticated caller.
func (h *DashboardHandler) PostRevokeSession(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	sessionID := r.PathValue("session_id")
	if sessionID == "" {
		http.Error(w, "session_id is required", http.StatusBadRequest)
		return
	}

	// Verify the session belongs to the caller by listing and matching.
	// This avoids a cross-user revocation attack (fail closed).
	userSessions, err := h.sessions.ListSessionsByUser(r.Context(), userID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "bff: dashboard: list sessions for revoke failed", "error", err)
		http.Error(w, "failed to revoke session", http.StatusInternalServerError)
		return
	}
	var owned bool
	for _, s := range userSessions {
		if s.ID == sessionID {
			owned = true
			break
		}
	}
	if !owned {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	if err := h.sessions.RevokeSession(r.Context(), sessionID); err != nil {
		h.logger.ErrorContext(r.Context(), "bff: dashboard: revoke session failed", "error", err)
		http.Error(w, "failed to revoke session", http.StatusInternalServerError)
		return
	}

	h.sessionRevokes.Inc(telemetry.Outcome(telemetry.OutcomeSuccess))
	http.Redirect(w, r, "/dashboard/sessions", http.StatusSeeOther)
}

// PostRevokeCredential removes a registered authenticator by credential_id.
// The credential must belong to the authenticated caller (enforced by
// DashboardCredentialStore.DeleteCredential cross-user guard).
func (h *DashboardHandler) PostRevokeCredential(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	credID := r.PathValue("credential_id")
	if credID == "" {
		http.Error(w, "credential_id is required", http.StatusBadRequest)
		return
	}

	if err := h.credentials.DeleteCredential(r.Context(), credID, userID); err != nil {
		h.logger.ErrorContext(r.Context(), "bff: dashboard: revoke credential failed", "error", err)
		http.Error(w, "credential not found or access denied", http.StatusNotFound)
		return
	}

	http.Redirect(w, r, "/dashboard/sessions", http.StatusSeeOther)
}

// GetRelayToggles renders the per-RP email-relay toggle view. When relay is not
// deployed (h.relay == nil), renders a disabled-toggle view (INVARIANT §4 —
// soft dependency; graceful absence).
func (h *DashboardHandler) GetRelayToggles(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	if h.relay == nil {
		// Relay not deployed — render graceful absence view.
		h.renderTemplate(w, r, "dashboard_relay.html", dashboardRelayData{RelayAbsent: true})
		return
	}

	addresses, err := h.relay.ListByUser(r.Context(), userID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "bff: dashboard: list relay addresses failed", "error", err)
		http.Error(w, "failed to load relay toggles", http.StatusInternalServerError)
		return
	}

	h.pageViews.Inc(telemetry.Endpoint(telemetry.EndpointRelay))
	h.renderTemplate(w, r, "dashboard_relay.html", dashboardRelayData{Addresses: addresses})
}

// PostDeactivateRelay deactivates a relay address (kill switch) by address_id.
// If relay is not deployed, returns 503 gracefully.
func (h *DashboardHandler) PostDeactivateRelay(w http.ResponseWriter, r *http.Request) {
	userID := UserIDFromContext(r.Context())
	if userID == "" {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	if h.relay == nil {
		http.Error(w, "relay service not available", http.StatusServiceUnavailable)
		return
	}

	addressID := r.PathValue("address_id")
	if addressID == "" {
		http.Error(w, "address_id is required", http.StatusBadRequest)
		return
	}

	// Verify ownership by listing — only addresses belonging to this user are
	// returned by ListByUser.
	addresses, err := h.relay.ListByUser(r.Context(), userID)
	if err != nil {
		h.logger.ErrorContext(r.Context(), "bff: dashboard: list relay for deactivate failed", "error", err)
		http.Error(w, "failed to deactivate relay", http.StatusInternalServerError)
		return
	}
	var owned bool
	for _, a := range addresses {
		if a.ID == addressID {
			owned = true
			break
		}
	}
	if !owned {
		http.Error(w, "relay address not found", http.StatusNotFound)
		return
	}

	if err := h.relay.Deactivate(r.Context(), addressID); err != nil {
		h.logger.ErrorContext(r.Context(), "bff: dashboard: deactivate relay failed", "error", err)
		http.Error(w, "failed to deactivate relay", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard/relay", http.StatusSeeOther)
}

// renderTemplate executes a named template with data. On error it logs and
// returns a 500 — it never leaks template internals.
func (h *DashboardHandler) renderTemplate(w http.ResponseWriter, r *http.Request, name string, data any) {
	if h.tmpl == nil {
		http.Error(w, "dashboard templates not configured", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, name, data); err != nil {
		h.logger.ErrorContext(r.Context(), "bff: dashboard: template render failed",
			"template", name, "error", err)
	}
}
