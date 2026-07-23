package mgmtapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/harbor-auth/harbor/internal/mfa"
)

// fakeMFAService is an in-memory MFAService for handler tests. Each method
// returns its configured error (or result) and records the arguments it was
// called with so tests can assert the handler forwards them correctly.
type fakeMFAService struct {
	enrollResult *mfa.EnrollResult
	enrollErr    error
	activateErr  error
	verifyErr    error
	recoveryErr  error
	listResult   []mfa.Factor
	listErr      error
	disableErr   error

	gotUserID string
	gotCode   string
	enrolled  bool
	activated bool
	verified  bool
	recovered bool
	listed    bool
	disabled  bool
}

func (f *fakeMFAService) Enroll(_ context.Context, userID string) (*mfa.EnrollResult, error) {
	f.enrolled = true
	f.gotUserID = userID
	if f.enrollErr != nil {
		return nil, f.enrollErr
	}
	if f.enrollResult != nil {
		return f.enrollResult, nil
	}
	return &mfa.EnrollResult{
		FactorID:        "factor-1",
		Secret:          "JBSWY3DPEHPK3PXP",
		ProvisioningURI: "otpauth://totp/Harbor:user-1?secret=JBSWY3DPEHPK3PXP&issuer=Harbor",
		RecoveryCodes:   []string{"CODE-1111", "CODE-2222"},
	}, nil
}

func (f *fakeMFAService) Activate(_ context.Context, userID, code string) error {
	f.activated = true
	f.gotUserID = userID
	f.gotCode = code
	return f.activateErr
}

func (f *fakeMFAService) Verify(_ context.Context, userID, code string) error {
	f.verified = true
	f.gotUserID = userID
	f.gotCode = code
	return f.verifyErr
}

func (f *fakeMFAService) VerifyRecoveryCode(_ context.Context, userID, code string) error {
	f.recovered = true
	f.gotUserID = userID
	f.gotCode = code
	return f.recoveryErr
}

func (f *fakeMFAService) ListFactors(_ context.Context, userID string) ([]mfa.Factor, error) {
	f.listed = true
	f.gotUserID = userID
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listResult, nil
}

func (f *fakeMFAService) Disable(_ context.Context, userID string) error {
	f.disabled = true
	f.gotUserID = userID
	return f.disableErr
}

// newMFAServer builds a Server with the given MFA service wired in.
func newMFAServer(svc MFAService) *Server {
	return New(nil, nil).WithMFA(svc)
}

// mfaRequest builds an authenticated (unless userID is empty) MFA request.
func mfaRequest(method, path, body, userID string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if userID != "" {
		r.Header.Set(UserIDHeader, userID)
	}
	return r
}

// --- POST /mfa/enroll ---

func TestPostMFAEnroll_Success(t *testing.T) {
	svc := &fakeMFAService{}
	s := newMFAServer(svc)

	rec := httptest.NewRecorder()
	s.PostMFAEnroll(rec, mfaRequest(http.MethodPost, "/mfa/enroll", "{}", "user-1"))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp mfaEnrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.FactorID != "factor-1" || resp.Secret == "" || resp.ProvisioningURI == "" {
		t.Errorf("response = %+v, want populated factor/secret/uri", resp)
	}
	if len(resp.RecoveryCodes) != 2 {
		t.Errorf("recovery codes = %d, want 2", len(resp.RecoveryCodes))
	}
	if !svc.enrolled || svc.gotUserID != "user-1" {
		t.Errorf("Enroll not called with user-1: %+v", svc)
	}
}

func TestPostMFAEnroll_AlreadyEnrolled(t *testing.T) {
	s := newMFAServer(&fakeMFAService{enrollErr: mfa.ErrAlreadyEnrolled})
	rec := httptest.NewRecorder()
	s.PostMFAEnroll(rec, mfaRequest(http.MethodPost, "/mfa/enroll", "{}", "user-1"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

func TestPostMFAEnroll_Unauthorized(t *testing.T) {
	s := newMFAServer(&fakeMFAService{})
	rec := httptest.NewRecorder()
	s.PostMFAEnroll(rec, mfaRequest(http.MethodPost, "/mfa/enroll", "{}", ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestPostMFAEnroll_Unavailable(t *testing.T) {
	s := New(nil, nil) // no MFA wired
	rec := httptest.NewRecorder()
	s.PostMFAEnroll(rec, mfaRequest(http.MethodPost, "/mfa/enroll", "{}", "user-1"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestPostMFAEnroll_ServerError(t *testing.T) {
	s := newMFAServer(&fakeMFAService{enrollErr: errors.New("db down")})
	rec := httptest.NewRecorder()
	s.PostMFAEnroll(rec, mfaRequest(http.MethodPost, "/mfa/enroll", "{}", "user-1"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// --- POST /mfa/activate ---

func TestPostMFAActivate_Success(t *testing.T) {
	svc := &fakeMFAService{}
	s := newMFAServer(svc)
	rec := httptest.NewRecorder()
	s.PostMFAActivate(rec, mfaRequest(http.MethodPost, "/mfa/activate", `{"code":"123456"}`, "user-1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !svc.activated || svc.gotCode != "123456" {
		t.Errorf("Activate not called correctly: %+v", svc)
	}
}

func TestPostMFAActivate_InvalidCode(t *testing.T) {
	s := newMFAServer(&fakeMFAService{activateErr: mfa.ErrInvalidCode})
	rec := httptest.NewRecorder()
	s.PostMFAActivate(rec, mfaRequest(http.MethodPost, "/mfa/activate", `{"code":"000000"}`, "user-1"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestPostMFAActivate_NotEnrolled(t *testing.T) {
	s := newMFAServer(&fakeMFAService{activateErr: mfa.ErrNotEnrolled})
	rec := httptest.NewRecorder()
	s.PostMFAActivate(rec, mfaRequest(http.MethodPost, "/mfa/activate", `{"code":"123456"}`, "user-1"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestPostMFAActivate_MalformedBody(t *testing.T) {
	s := newMFAServer(&fakeMFAService{})
	rec := httptest.NewRecorder()
	s.PostMFAActivate(rec, mfaRequest(http.MethodPost, "/mfa/activate", `{not json`, "user-1"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestPostMFAActivate_MissingCode(t *testing.T) {
	svc := &fakeMFAService{}
	s := newMFAServer(svc)
	rec := httptest.NewRecorder()
	s.PostMFAActivate(rec, mfaRequest(http.MethodPost, "/mfa/activate", `{}`, "user-1"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if svc.activated {
		t.Error("Activate must not be called when code is missing")
	}
}

func TestPostMFAActivate_Unauthorized(t *testing.T) {
	s := newMFAServer(&fakeMFAService{})
	rec := httptest.NewRecorder()
	s.PostMFAActivate(rec, mfaRequest(http.MethodPost, "/mfa/activate", `{"code":"123456"}`, ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestPostMFAActivate_Unavailable(t *testing.T) {
	s := New(nil, nil)
	rec := httptest.NewRecorder()
	s.PostMFAActivate(rec, mfaRequest(http.MethodPost, "/mfa/activate", `{"code":"123456"}`, "user-1"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// --- POST /mfa/verify ---

func TestPostMFAVerify_Success(t *testing.T) {
	svc := &fakeMFAService{}
	s := newMFAServer(svc)
	rec := httptest.NewRecorder()
	s.PostMFAVerify(rec, mfaRequest(http.MethodPost, "/mfa/verify", `{"code":"123456"}`, "user-1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !svc.verified || svc.gotCode != "123456" {
		t.Errorf("Verify not called correctly: %+v", svc)
	}
}

func TestPostMFAVerify_InvalidCode(t *testing.T) {
	s := newMFAServer(&fakeMFAService{verifyErr: mfa.ErrInvalidCode})
	rec := httptest.NewRecorder()
	s.PostMFAVerify(rec, mfaRequest(http.MethodPost, "/mfa/verify", `{"code":"000000"}`, "user-1"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestPostMFAVerify_NotEnrolled(t *testing.T) {
	s := newMFAServer(&fakeMFAService{verifyErr: mfa.ErrNotEnrolled})
	rec := httptest.NewRecorder()
	s.PostMFAVerify(rec, mfaRequest(http.MethodPost, "/mfa/verify", `{"code":"123456"}`, "user-1"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestPostMFAVerify_Unauthorized(t *testing.T) {
	s := newMFAServer(&fakeMFAService{})
	rec := httptest.NewRecorder()
	s.PostMFAVerify(rec, mfaRequest(http.MethodPost, "/mfa/verify", `{"code":"123456"}`, ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestPostMFAVerify_Unavailable(t *testing.T) {
	s := New(nil, nil)
	rec := httptest.NewRecorder()
	s.PostMFAVerify(rec, mfaRequest(http.MethodPost, "/mfa/verify", `{"code":"123456"}`, "user-1"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// --- POST /mfa/verify-recovery ---

func TestPostMFAVerifyRecovery_Success(t *testing.T) {
	svc := &fakeMFAService{}
	s := newMFAServer(svc)
	rec := httptest.NewRecorder()
	s.PostMFAVerifyRecovery(rec, mfaRequest(http.MethodPost, "/mfa/verify-recovery", `{"code":"CODE-1111"}`, "user-1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !svc.recovered || svc.gotCode != "CODE-1111" {
		t.Errorf("VerifyRecoveryCode not called correctly: %+v", svc)
	}
}

func TestPostMFAVerifyRecovery_InvalidCode(t *testing.T) {
	s := newMFAServer(&fakeMFAService{recoveryErr: mfa.ErrInvalidCode})
	rec := httptest.NewRecorder()
	s.PostMFAVerifyRecovery(rec, mfaRequest(http.MethodPost, "/mfa/verify-recovery", `{"code":"WRONG"}`, "user-1"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestPostMFAVerifyRecovery_MalformedBody(t *testing.T) {
	s := newMFAServer(&fakeMFAService{})
	rec := httptest.NewRecorder()
	s.PostMFAVerifyRecovery(rec, mfaRequest(http.MethodPost, "/mfa/verify-recovery", `{not json`, "user-1"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestPostMFAVerifyRecovery_Unauthorized(t *testing.T) {
	s := newMFAServer(&fakeMFAService{})
	rec := httptest.NewRecorder()
	s.PostMFAVerifyRecovery(rec, mfaRequest(http.MethodPost, "/mfa/verify-recovery", `{"code":"CODE-1111"}`, ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestPostMFAVerifyRecovery_Unavailable(t *testing.T) {
	s := New(nil, nil)
	rec := httptest.NewRecorder()
	s.PostMFAVerifyRecovery(rec, mfaRequest(http.MethodPost, "/mfa/verify-recovery", `{"code":"CODE-1111"}`, "user-1"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// --- GET /mfa/factors ---

func TestGetMFAFactors_Success(t *testing.T) {
	svc := &fakeMFAService{listResult: []mfa.Factor{
		{ID: "f1", Type: mfa.FactorTypeTOTP, Used: true, CreatedAt: time.Unix(1700000000, 0)},
		{ID: "f2", Type: mfa.FactorTypeRecovery, Used: false, CreatedAt: time.Unix(1700000001, 0)},
	}}
	s := newMFAServer(svc)
	rec := httptest.NewRecorder()
	s.GetMFAFactors(rec, mfaRequest(http.MethodGet, "/mfa/factors", "", "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp mfaFactorsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 2 || len(resp.Factors) != 2 {
		t.Errorf("count = %d / factors = %d, want 2", resp.Count, len(resp.Factors))
	}
	if resp.Factors[0].ID != "f1" || resp.Factors[0].Type != string(mfa.FactorTypeTOTP) {
		t.Errorf("factor[0] = %+v, want {f1 totp ...}", resp.Factors[0])
	}
}

func TestGetMFAFactors_EmptyIsArray(t *testing.T) {
	s := newMFAServer(&fakeMFAService{}) // nil listResult
	rec := httptest.NewRecorder()
	s.GetMFAFactors(rec, mfaRequest(http.MethodGet, "/mfa/factors", "", "user-1"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// An empty list must serialize as [] (not null) so clients can iterate.
	if !strings.Contains(rec.Body.String(), `"factors":[]`) {
		t.Errorf("body = %s, want factors:[]", rec.Body.String())
	}
}

func TestGetMFAFactors_Unauthorized(t *testing.T) {
	s := newMFAServer(&fakeMFAService{})
	rec := httptest.NewRecorder()
	s.GetMFAFactors(rec, mfaRequest(http.MethodGet, "/mfa/factors", "", ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestGetMFAFactors_Unavailable(t *testing.T) {
	s := New(nil, nil)
	rec := httptest.NewRecorder()
	s.GetMFAFactors(rec, mfaRequest(http.MethodGet, "/mfa/factors", "", "user-1"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestGetMFAFactors_ListError(t *testing.T) {
	s := newMFAServer(&fakeMFAService{listErr: errors.New("db down")})
	rec := httptest.NewRecorder()
	s.GetMFAFactors(rec, mfaRequest(http.MethodGet, "/mfa/factors", "", "user-1"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// --- DELETE /mfa/factors/{id} ---

// deleteMFAFactor routes a DELETE through the mux so the {id} path value is set.
func deleteMFAFactor(s *Server, id, userID string) *httptest.ResponseRecorder {
	mux := http.NewServeMux()
	s.Routes(mux)
	req := httptest.NewRequest(http.MethodDelete, "/mfa/factors/"+id, nil)
	if userID != "" {
		req.Header.Set(UserIDHeader, userID)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestDeleteMFAFactor_Success(t *testing.T) {
	svc := &fakeMFAService{}
	s := newMFAServer(svc)
	rec := deleteMFAFactor(s, "factor-1", "user-1")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", rec.Code, rec.Body.String())
	}
	if !svc.disabled || svc.gotUserID != "user-1" {
		t.Errorf("Disable not called with user-1: %+v", svc)
	}
}

func TestDeleteMFAFactor_Unauthorized(t *testing.T) {
	s := newMFAServer(&fakeMFAService{})
	rec := deleteMFAFactor(s, "factor-1", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestDeleteMFAFactor_Unavailable(t *testing.T) {
	s := New(nil, nil)
	rec := deleteMFAFactor(s, "factor-1", "user-1")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestDeleteMFAFactor_DisableError(t *testing.T) {
	s := newMFAServer(&fakeMFAService{disableErr: errors.New("db down")})
	rec := deleteMFAFactor(s, "factor-1", "user-1")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

// --- routing ---

func TestRoutesRegistersMFA(t *testing.T) {
	svc := &fakeMFAService{}
	s := newMFAServer(svc)
	mux := http.NewServeMux()
	s.Routes(mux)

	req := httptest.NewRequest(http.MethodPost, "/mfa/enroll", strings.NewReader("{}"))
	req.Header.Set(UserIDHeader, "user-1")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("routed status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
}
