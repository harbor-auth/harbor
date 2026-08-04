package bff

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"
)

// TestSigninHandler_BeginLoginScript_UnwrapsPublicKeyWrapper renders the real
// /signin page, extracts its inline script verbatim, and runs it under Node
// against a fetch mock shaped exactly like BeginLogin's actual response:
// protocol.CredentialAssertion (see BeginLogin, internal/bff/login.go)
// serializes as {"publicKey": {"challenge": ..., "allowCredentials": ...}},
// per its Response field's `json:"publicKey"` tag in
// go-webauthn/protocol/options.go. It proves beginLogin() unwraps that
// envelope before calling decodeAssertionOptions, so
// navigator.credentials.get() is reached with a real ArrayBuffer challenge
// instead of decodeAssertionOptions throwing a TypeError on
// options.challenge === undefined (options.challenge/allowCredentials read
// off the top level of the still-wrapped body).
func TestSigninHandler_BeginLoginScript_UnwrapsPublicKeyWrapper(t *testing.T) {
	requireNode(t)
	script := extractSigninScript(t)
	runNodeHarness(t, signinScriptTestHarness(script))
}

// requireNode fails the calling test closed when no Node.js binary is
// available to run the extracted inline script under. Node is a pinned
// member of the hermetic dev shell (flake.nix), so its absence here means the
// toolchain isn't the one CI/`make test` expect — surface that loudly rather
// than silently skipping real signin-script coverage (Foundation F3).
func requireNode(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatalf("node not available in PATH (required by the pinned dev shell — run under `nix develop`): %v", err)
	}
}

// extractSigninScript renders the real /signin page and returns its inline
// <script> block verbatim, so tests exercise the actual production script
// text rather than a reimplementation of its logic.
func extractSigninScript(t *testing.T) string {
	t.Helper()
	store := NewInMemoryBFFSessionStore()
	handler, err := NewSigninHandler(store, testSigninTemplates(t), 5*time.Minute, nil, nil)
	if err != nil {
		t.Fatalf("NewSigninHandler: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/signin", nil)
	rec := httptest.NewRecorder()
	handler.ServeSignin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()

	const openTag, closeTag = "<script>", "</script>"
	start := strings.Index(body, openTag)
	end := strings.Index(body, closeTag)
	if start == -1 || end == -1 || end < start {
		t.Fatal("could not locate inline <script> block in rendered /signin page")
	}
	return body[start+len(openTag) : end]
}

// runNodeHarness writes source to a temp file, runs it under Node, and fails
// the test unless it reports PASS. Callers must call requireNode(t) first.
func runNodeHarness(t *testing.T, source string) {
	t.Helper()
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Fatalf("node not available in PATH (requireNode(t) should have failed already): %v", err)
	}

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "signin_test.js")
	if err := os.WriteFile(scriptPath, []byte(source), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}

	cmd := exec.Command(nodePath, scriptPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node harness failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Fatalf("node harness did not report PASS:\n%s", out)
	}
}

// signinScriptTestHarness wraps the page's real inline script in a minimal
// browser-shaped environment: it registers the click handler, fires it, and
// asserts navigator.credentials.get() is reached with a correctly decoded
// challenge/allowCredentials rather than the ceremony silently dying inside
// decodeAssertionOptions.
func signinScriptTestHarness(script string) string {
	return fmt.Sprintf(`"use strict";

const assert = require("assert");

const listeners = {};
const button = { disabled: false, addEventListener(type, cb) { listeners[type] = cb; } };
const statusEl = { textContent: "", classList: { toggle() {} } };

global.document = {
  getElementById(id) {
    if (id === "signin-button") return button;
    if (id === "signin-status") return statusEl;
    throw new Error("unexpected getElementById: " + id);
  }
};

global.PublicKeyCredential = {};
global.window = { atob: global.atob, btoa: global.btoa, PublicKeyCredential: global.PublicKeyCredential, location: { assign() {} } };

let getCallArgs = null;
Object.defineProperty(global, "navigator", {
  configurable: true,
  value: {
    credentials: {
      get(options) {
        getCallArgs = options;
        return Promise.resolve(null);
      }
    }
  }
});

global.fetch = (url) => {
  if (String(url).indexOf("/login?") !== 0) {
    return Promise.reject(new Error("unexpected fetch: " + url));
  }
  return Promise.resolve({
    ok: true,
    json: () => Promise.resolve({
      publicKey: {
        challenge: "Y2hhbGxlbmdl",
        timeout: 60000,
        rpId: "example.com",
        userVerification: "preferred",
        allowCredentials: [{ id: "aWQtMQ", type: "public-key" }]
      },
      mediation: "conditional"
    })
  });
};

%s

listeners.click();

(async () => {
  await new Promise((resolve) => setTimeout(resolve, 100));

  assert(getCallArgs, "navigator.credentials.get() was never called -- decodeAssertionOptions likely threw on the raw {publicKey:...} envelope");
  assert(getCallArgs.publicKey, "options passed to navigator.credentials.get() are missing publicKey");

  const challenge = Buffer.from(getCallArgs.publicKey.challenge);
  assert.deepStrictEqual(challenge, Buffer.from("challenge", "utf8"), "challenge was not decoded from the wrapped publicKey.challenge");

  assert(Array.isArray(getCallArgs.publicKey.allowCredentials) && getCallArgs.publicKey.allowCredentials.length === 1, "allowCredentials missing");
  const credID = Buffer.from(getCallArgs.publicKey.allowCredentials[0].id);
  assert.deepStrictEqual(credID, Buffer.from("id-1", "utf8"), "allowCredentials[0].id was not decoded from the wrapped publicKey.allowCredentials");

  console.log("PASS");
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
`, script)
}

// signinScenarioParams configures signinScenarioHarness: it decides whether
// the passive conditional-mediation attempt arms on load, how
// navigator.credentials.get() and POST /login/complete behave, and whether
// the accessible button is clicked — then asserts the resulting status text,
// error styling, button state, and navigation.
type signinScenarioParams struct {
	Script                        string
	ConditionalMediationAvailable bool
	CredentialsGetImpl            string // body of navigator.credentials.get(options)
	LoginCompleteImpl             string // body of the POST /login/complete fetch branch
	ClickButton                   bool
	Assertions                    string // raw JS run after settling, before console.log("PASS")
}

var signinScenarioHarnessTmpl = template.Must(template.New("signinScenario").Parse(`"use strict";

const assert = require("assert");

const listeners = {};
const button = { disabled: false, addEventListener(type, cb) { listeners[type] = cb; } };
const statusEl = { textContent: "", _error: false, classList: { toggle(cls, on) { statusEl._error = Boolean(on); } } };

global.document = {
  getElementById(id) {
    if (id === "signin-button") return button;
    if (id === "signin-status") return statusEl;
    throw new Error("unexpected getElementById: " + id);
  }
};

let assignedTo = null;
global.PublicKeyCredential = {{if .ConditionalMediationAvailable}}{ isConditionalMediationAvailable: () => Promise.resolve(true) }{{else}}{}{{end}};
global.window = { atob: global.atob, btoa: global.btoa, PublicKeyCredential: global.PublicKeyCredential, location: { assign(url) { assignedTo = url; } } };

Object.defineProperty(global, "navigator", {
  configurable: true,
  value: {
    credentials: {
      get(options) {
        {{.CredentialsGetImpl}}
      }
    }
  }
});

global.fetch = (url, init) => {
  if (String(url).indexOf("/login?") === 0) {
    return Promise.resolve({
      ok: true,
      json: () => Promise.resolve({
        publicKey: {
          challenge: "Y2hhbGxlbmdl",
          timeout: 60000,
          rpId: "example.com",
          userVerification: "preferred",
          allowCredentials: [{ id: "aWQtMQ", type: "public-key" }]
        },
        mediation: "conditional"
      })
    });
  }
  if (String(url) === "/login/complete") {
    {{.LoginCompleteImpl}}
  }
  return Promise.reject(new Error("unexpected fetch: " + url));
};

{{.Script}}

(async () => {
  // Let any passive conditional-mediation attempt armed on load run to
  // completion before the button is (maybe) clicked.
  await new Promise((resolve) => setTimeout(resolve, 30));

  {{if .ClickButton}}
  assert(!button.disabled, "button must remain enabled and clickable while a passive attempt is pending");
  listeners.click();
  {{end}}

  await new Promise((resolve) => setTimeout(resolve, 30));

  {{.Assertions}}

  console.log("PASS");
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
`))

// signinScenarioHarness renders signinScenarioHarnessTmpl into runnable JS.
func signinScenarioHarness(t *testing.T, p signinScenarioParams) string {
	t.Helper()
	var buf strings.Builder
	if err := signinScenarioHarnessTmpl.Execute(&buf, p); err != nil {
		t.Fatalf("execute harness template: %v", err)
	}
	return buf.String()
}

// notAllowedErrorRejection is a WebAuthn-shaped rejection: the error real
// browsers surface for both an explicit user cancellation and a passive
// conditional-mediation request that found nothing to offer.
const notAllowedErrorRejection = `return Promise.reject(Object.assign(new Error("The operation either timed out or was not allowed."), { name: "NotAllowedError" }));`

const unreachableLoginComplete = `return Promise.reject(new Error("finishLogin must not be reached in this scenario"));`

// TestSigninHandler_SigninScript_PassiveNoCredentialStaysSilent covers the
// blocking visual-QA finding (task ftask_944bb8cd..., attachment
// att_765c5040-6173-4c68-88bb-8ad6bcecb7ed): a browser that reports
// conditional mediation available but resolves navigator.credentials.get()
// with no usable credential before the user has touched anything must never
// paint the generic red failure text — the accessible button stays the
// silent fallback.
func TestSigninHandler_SigninScript_PassiveNoCredentialStaysSilent(t *testing.T) {
	requireNode(t)
	script := extractSigninScript(t)
	runNodeHarness(t, signinScenarioHarness(t, signinScenarioParams{
		Script:                        script,
		ConditionalMediationAvailable: true,
		CredentialsGetImpl:            `return Promise.resolve(null);`,
		LoginCompleteImpl:             unreachableLoginComplete,
		ClickButton:                   false,
		Assertions: `
  assert.strictEqual(statusEl.textContent, "", "no-credential passive outcome must not set any status text");
  assert.strictEqual(statusEl._error, false, "no-credential passive outcome must not add the error style");
  assert.strictEqual(button.disabled, false, "the accessible button must remain enabled after a silent passive failure");
`,
	}))
}

// TestSigninHandler_SigninScript_PassiveCancellationStaysSilent covers the
// same finding for the other passive failure shape: the browser rejects with
// NotAllowedError (a passive-picker dismissal/timeout) rather than resolving
// null. This must also stay silent.
func TestSigninHandler_SigninScript_PassiveCancellationStaysSilent(t *testing.T) {
	requireNode(t)
	script := extractSigninScript(t)
	runNodeHarness(t, signinScenarioHarness(t, signinScenarioParams{
		Script:                        script,
		ConditionalMediationAvailable: true,
		CredentialsGetImpl:            notAllowedErrorRejection,
		LoginCompleteImpl:             unreachableLoginComplete,
		ClickButton:                   false,
		Assertions: `
  assert.strictEqual(statusEl.textContent, "", "passive cancellation must not set any status text");
  assert.strictEqual(statusEl._error, false, "passive cancellation must not add the error style");
  assert.strictEqual(button.disabled, false, "the accessible button must remain enabled after a silent passive cancellation");
`,
	}))
}

// TestSigninHandler_SigninScript_ExplicitFailureShowsGenericError proves the
// fix is scoped to passive attempts only: a button-triggered (explicit)
// attempt that fails the same way (NotAllowedError) must still surface the
// existing generic, account-existence-safe error message.
func TestSigninHandler_SigninScript_ExplicitFailureShowsGenericError(t *testing.T) {
	requireNode(t)
	script := extractSigninScript(t)
	runNodeHarness(t, signinScenarioHarness(t, signinScenarioParams{
		Script:                        script,
		ConditionalMediationAvailable: false,
		CredentialsGetImpl:            notAllowedErrorRejection,
		LoginCompleteImpl:             unreachableLoginComplete,
		ClickButton:                   true,
		Assertions: `
  assert.strictEqual(statusEl.textContent, "We couldn't sign you in with that passkey. Please try again.", "an explicit failed attempt must show the generic error");
  assert.strictEqual(statusEl._error, true, "an explicit failed attempt must add the error style");
  assert.strictEqual(button.disabled, false, "the button must be re-enabled after an explicit failure");
`,
	}))
}

// TestSigninHandler_SigninScript_SuccessfulDiscoverableSigninNavigates proves
// the fix does not affect the success path: a passive attempt that resolves
// a real credential must still complete sign-in and navigate to return_to,
// without ever touching the error status.
func TestSigninHandler_SigninScript_SuccessfulDiscoverableSigninNavigates(t *testing.T) {
	requireNode(t)
	script := extractSigninScript(t)
	runNodeHarness(t, signinScenarioHarness(t, signinScenarioParams{
		Script:                        script,
		ConditionalMediationAvailable: true,
		CredentialsGetImpl: `
        return Promise.resolve({
          id: "credential-id",
          rawId: new TextEncoder().encode("credential-id").buffer,
          type: "public-key",
          response: {
            clientDataJSON: new TextEncoder().encode("client-data").buffer,
            authenticatorData: new TextEncoder().encode("auth-data").buffer,
            signature: new TextEncoder().encode("sig").buffer,
            userHandle: new TextEncoder().encode("user-handle").buffer
          }
        });
`,
		LoginCompleteImpl: `return Promise.resolve({ type: "opaqueredirect", status: 0 });`,
		ClickButton:       false,
		Assertions: `
  assert.strictEqual(assignedTo, "/", "a successful passive sign-in must navigate to the page's return_to");
  assert.strictEqual(statusEl.textContent, "", "a successful passive sign-in must never touch the error status");
  assert.strictEqual(statusEl._error, false, "a successful passive sign-in must never add the error style");
`,
	}))
}

// TestSigninHandler_SigninScript_ExplicitAttemptAbortsPassiveWithoutError
// proves a newer explicit (button-triggered) attempt cleanly supersedes an
// in-flight passive one -- the aborted passive attempt's rejection must not
// flash the generic error before the explicit attempt's own outcome lands.
func TestSigninHandler_SigninScript_ExplicitAttemptAbortsPassiveWithoutError(t *testing.T) {
	requireNode(t)
	script := extractSigninScript(t)
	runNodeHarness(t, signinScenarioHarness(t, signinScenarioParams{
		Script:                        script,
		ConditionalMediationAvailable: true,
		// Every call to get() (passive, then explicit) hangs until aborted,
		// mirroring a real in-flight WebAuthn ceremony; only the abort should
		// ever resolve it.
		CredentialsGetImpl: `
        return new Promise((resolve, reject) => {
          options.signal.addEventListener("abort", () => {
            const err = new Error("aborted");
            err.name = "AbortError";
            reject(err);
          });
        });
`,
		LoginCompleteImpl: unreachableLoginComplete,
		ClickButton:       true,
		Assertions: `
  assert.strictEqual(statusEl.textContent, "", "an aborted passive attempt must never flash the generic error");
  assert.strictEqual(statusEl._error, false, "an aborted passive attempt must never add the error style");
`,
	}))
}
