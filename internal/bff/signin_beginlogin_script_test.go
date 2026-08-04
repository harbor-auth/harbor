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
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available in PATH")
	}

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
	script := body[start+len(openTag) : end]

	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "signin_test.js")
	if err := os.WriteFile(scriptPath, []byte(signinScriptTestHarness(script)), 0o600); err != nil {
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
