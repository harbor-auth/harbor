# Cross-site RP sign-in browser binding

Fresh Moustache sign-ins failed before the passkey page because the anonymous
browser nonce used `SameSite=Strict`. Chrome withheld it across the external RP
redirect chain from `/authorize` to `/signin`.

- [x] A. Reproduce the exact error against production using an isolated browser profile and the registered Moustache callback.
- [x] B. Set and clear only the anonymous nonce cookie with explicit `SameSite=Lax`; retain authenticated-cookie policy, live-transaction binding, expiry, CSRF guards and PKCE.
- [x] C. Add a browser regression through the real hot HTTP chain and sign-in handler using migrated PostgreSQL and Redis, preserving the RP transaction and rejecting missing/wrong nonces. Confirm it fails before the fix and passes afterwards.
- [x] D. Complete cumulative review, pattern audit and required local checks.

Validation: full unit and integration suites passed with the race detector;
the hot startup/browser package passed explicitly after the final test edit.
Lint reported zero issues, F5 found no test weakening, and security-package
coverage was 80.6% against the 75% floor. Review and pattern audit found no
remaining required fixes.

Release the source through CI, promote signed images through the deployment PR,
then verify production convergence and repeat the Moustache authorization probe.
The source and deployment PRs record the release result.

The production probe stops at the passkey page; it does not complete the user's
physical passkey ceremony or create an account.
