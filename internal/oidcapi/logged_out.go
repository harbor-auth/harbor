package oidcapi

import "net/http"

// GetLoggedOut serves the default post-logout destination page: GET /logged-out.
// This is where users land after RP-Initiated Logout when no valid
// post_logout_redirect_uri was provided, or when the RP omitted one entirely.
// The page confirms logout completion with a minimal, PII-free message.
func (s *Server) GetLoggedOut(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Prevent caching so a Back button doesn't show a stale "logged out" page
	// when the user has since re-authenticated.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(loggedOutHTML))
}

// loggedOutHTML is a minimal, self-contained HTML page confirming logout. It
// carries no PII, no external resources (CSP-friendly), and no JavaScript.
const loggedOutHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Logged Out</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
      background: #f5f5f5;
      color: #333;
    }
    .container {
      text-align: center;
      padding: 2rem;
    }
    h1 {
      font-size: 1.5rem;
      font-weight: 500;
      margin-bottom: 0.5rem;
    }
    p {
      color: #666;
      margin: 0;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>You have been logged out</h1>
    <p>You may close this window.</p>
  </div>
</body>
</html>`
