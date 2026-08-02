# Add failing tests for required service collaborators

1. Identify the security-critical collaborators currently defaulted to no-op or
   deferred to runtime 501/503 responses in OIDC, management, WebAuthn, and the
   dashboard.
2. Add constructor-focused negative tests in the four assigned test files,
   preserving explicitly optional dependencies such as loggers and relay.
3. Run the focused packages and confirm the new tests fail for the intended
   missing-dependency behavior, then commit and push the test-first checkpoint.

