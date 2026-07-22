# fix-auth-bypass — Tasks

> Plan: `docs/plans/fix-auth-bypass.md` · Blocker 1.1 in
> `docs/plans/production-readiness.md`. Pure wiring fix in
> `cmd/harbor-hot/main.go` consuming the completed `bff-flow-wiring` seam.

## 1. Wiring — `cmd/harbor-hot/main.go`

- [ ] Construct the BFF session store: Redis-backed when `REDIS_URL` is set;
      in-memory fallback only with a loud `logger.Warn("dev only")`.
- [ ] Pass `BFFSessions` + `LoginURL` (env `LOGIN_URL`) + `BFFSessionTTL` into
      `oidcapi.Config` so `/authorize` uses the BFF flow
      (`ValidateAuthorizeRequest` → session → redirect to login UI), not the
      legacy immediate-code `Authorize` path.
- [ ] Replace `oidc.NewStubSessionResolver("demo-user-ppid")` with
      `oidc.NewPPIDSessionResolver(PPIDSessionResolverConfig{Auth: bff.NewBFFAuthSource(), Loader: ..., Grants: ...})`.
- [ ] DB path (`DATABASE_URL` set): wire the DB-backed `UserSecretLoader`
      (`clients.DBSecretLoader`) and DB `GrantStore`; delete the
      `oidc.NewFixedAuthSource("00000000-0000-0000-0000-000000000001")` wiring
      and its "SCAFFOLD" confession comment.
- [ ] Startup fail-closed guard: production configuration (e.g.
      `DATABASE_URL` set or `HARBOR_ENV=production`) without a fully
      configured BFF flow (`LOGIN_URL` + session store) → refuse to start with
      a clear error message.
- [ ] Remove any remaining non-test references to `NewFixedAuthSource` /
      `NewStubSessionResolver` under `cmd/` (check `cmd/harbor-mgmt` too).

## 2. Kubernetes / config

- [ ] Add `LOGIN_URL` to the harbor-hot Deployment env (ArgoCD/Helm values)
      pointing at the mgmt login UI.
- [ ] Document the new env vars in the harbor-hot package doc comment
      (top of `main.go`) and README/deploy docs.

## 3. Tests

- [ ] Wiring/e2e test: with BFF configured, `GET /authorize` (valid client,
      PKCE, state) returns 302 to the login URL and creates a BFF session —
      never a code.
- [ ] E2E: full passkey login → `/authorize/complete` → code → `/token`;
      assert token `sub` is the logged-in user's PPID; two distinct users get
      distinct `sub`s for the same client.
- [ ] Negative: `/authorize/complete` with no authenticated BFF session →
      error, no code minted (`BFFAuthSource` → `ErrNotAuthenticated` path).
- [ ] Guard test/CI grep: `NewFixedAuthSource|NewStubSessionResolver` absent
      from all non-`_test.go` files under `cmd/`.
- [ ] `go build ./... && go test ./...` green.

## 4. Docs / hygiene

- [ ] Strike blocker 1.1 in `docs/plans/production-readiness.md` (move to a
      Resolved note) in the same change.
- [ ] No scaffold code or "SCAFFOLD" comments remain on the production wiring
      path for auth identity.
