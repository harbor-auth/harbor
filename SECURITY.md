# Security Policy

Harbor is a privacy-first OpenID Provider. Because it sits on the authentication
critical path, we take security reports seriously and want to make responsible
disclosure easy.

> [!IMPORTANT]
> **Harbor is pre-production scaffold software.** It is **not** hardened for and
> **must not** be used to secure real user traffic yet. Several deliberate
> dev-only scaffolds (e.g. `FixedAuthSource`, in-memory stores, an in-process
> signing key) are documented as such in the code and in the
> [production-readiness audit](docs/plans/production-readiness.md). Please read
> that audit before reporting an issue — if a behaviour is already listed there
> as a known, labelled scaffold, it is not a new vulnerability.

## Supported versions

Harbor has **no stable release yet**. It is in the *foundation / scaffolding*
phase (see the [README status](README.md#status)). Until a `v1.0.0` tag is cut,
only the `main` branch is supported, and security fixes land on `main`.

| Version | Supported |
|---|---|
| `main` (unreleased) | ✅ fixes land here |
| any tag < `v1.0.0` | ⚠️ pre-release, no support guarantee |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through **GitHub Private Vulnerability Reporting**:

1. Go to the [Security tab](https://github.com/harbor-auth/harbor/security) of
   this repository.
2. Click **Report a vulnerability**.
3. Fill in the advisory form with the details below.

If you cannot use GitHub's private reporting, open a minimal issue asking a
maintainer to contact you privately — **without** any vulnerability details.

### What to include

A good report contains:

- **Affected component** — binary (`harbor-hot` / `harbor-mgmt`), package, and
  file/endpoint.
- **Impact** — what an attacker can do (auth bypass, PII leak, key exposure,
  cross-region data movement, etc.). Data-sovereignty and PPID-correlation
  issues are in scope and treated as high severity.
- **Reproduction** — minimal steps, a request/response trace, or a failing test.
- **Version** — the commit SHA of `main` you tested against.
- **Suggested fix** — optional, but appreciated.

## Response timeline

We aim to:

| Stage | Target |
|---|---|
| Acknowledge your report | within **3 business days** |
| Initial assessment + severity | within **7 business days** |
| Fix or mitigation plan | depends on severity; we will keep you updated |

We will coordinate a disclosure timeline with you and credit you in the advisory
unless you prefer to remain anonymous.

## Known limitations

Harbor's current, deliberately-incomplete state is documented in full in the
[**production-readiness audit**](docs/plans/production-readiness.md). It
enumerates the critical blockers (auth bypass scaffolds, missing HSM/KMS,
unauthenticated admin endpoints, absent client auth) that **must** be resolved
before any production traffic. Reports that simply restate an item already
tracked there are not treated as new vulnerabilities, but reports that
demonstrate a *new* or *worse-than-documented* impact are very welcome.
