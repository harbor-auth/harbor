# BFF browser nonce gate regression tests

1. Add a BeginLogin regression test for a valid session with no BrowserNonceHash, asserting fail-closed behavior and no WebAuthn or cookie side effects.
2. Add a FinishLoginWithParsedData regression test for a valid session with no BrowserNonceHash, asserting fail-closed behavior and no WebAuthn, redirect, or session mutation side effects.
3. Run the focused tests to verify they fail against the current fail-open implementation, then format, commit, rebase, and push the test-only change.
4. Add an authorization-completion regression test for an authenticated session whose BrowserNonceHash is absent, asserting the no-redirect error page and no issued code.
5. Run the focused authorization-completion test to verify it fails against the current fail-open implementation, then retain and run the full BFF flow proving /authorize supplies a matching hash and cookie.
