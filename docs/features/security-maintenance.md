---
title: October 2026 security maintenance
status: implemented
design_refs: [§7.3, §4.4, §1.8]
code: [deploy/openbao/values.yaml, deploy/ingress/, deploy/Dockerfile.hot, deploy/Dockerfile.mgmt, deploy/Dockerfile.migrate, go.mod, sdk/sign-in-button/react/package-lock.json, .github/workflows/security.yml]
tests: [internal/crypto/, internal/oidc/, internal/oidcapi/, deploy/contract/]
last_reconciled: 2026-10-22
---

# October 2026 security maintenance

The October 22 production inspection found running OpenBao 2.6.2, Traefik
3.7.12, Argo CD 3.4.8 and Harbor binaries built with Go 1.26.8. These versions
predate September/October security fixes. This document records the patch set;
release evidence must distinguish repository changes from deployed versions.

## Patches

- OpenBao 2.6.4, immutable amd64 digest: covers CVE-2026-104090
  (privileged Raft snapshot/plugin RCE), CVE-2026-104093 (ACL canonicalization),
  CVE-2026-104092 (PKI SAN validation), and subsequent fixes including
  GHSA-gf3j-hm38-jhh5 (Kubernetes token renewal after revocation).
- Traefik 3.7.16, immutable amd64 digest: covers September routing/header fixes
  including CVE-2026-88004, CVE-2026-88008 and CVE-2026-88009, plus October
  connection isolation and ingress-NGINX provider fixes. Both core/cloud
  definitions are patched; host-owned copies live in harbor-cloud's
  `infra/host/k3s/`.
- Argo CD 3.4.10: its publisher-signed image index is pinned in harbor-cloud's
  core/cloud bootstrap charts. It fixes CVE-2026-113708/113709 repo-server RCE,
  CVE-2026-113672 file disclosure and other advisories. Installed chart 10.2.2
  is explicitly retained. Repository and Application access remain privileged.
- Harbor builds use Go 1.26.10, including October HTTP/TLS/template fixes and
  CVE-2026-111943 compromised-intermediate distrust. Nix moves to a compatible
  pinned 26.05 channel; patched kin-openapi requires Go 1.26. The SDK, generated
  code and cryptographic golden tests are checked against that toolchain.
- kin-openapi 0.149.0 covers CVE-2026-100347/348/349/351/352/353/354.
  `golang.org/x/net` moves to 0.60.0 with its compatible crypto/text/system
  dependencies, covering the separate HTTP/2 library fixes.
- The React SDK lockfile updates Vite, source-map-js and undici transitive
  dependencies. npm audit reported zero vulnerabilities after the update.

## Verification and release controls

The Go source scan reports no affected reachable symbols or imported packages.
One module-level notice remains: deprecated `x/crypto/openpgp` has no patch.
Harbor does not import that package. It is not treated as a reachable runtime
finding; the module is required for other cryptography.

CI now runs pinned govulncheck against production commands and audits all SDK
npm dependencies, including development tooling. A clean source scan does not
prove absence of OS, infrastructure, or configuration vulnerabilities.

Before the OpenBao update, an encrypted Raft snapshot was captured with mode
0600 outside the repository. Existing OVH seal configuration and PVCs must be
preserved. The snapshot is not an independent offline recovery test. Argo CD
image publisher identity/signature was verified, all four host charts rendered,
and their manifests passed target-cluster server-side dry runs; only version
pins differed from live values. OpenBao's chart rendered successfully.

## References

- [OpenBao security releases](https://openbao.org/community/release-notes/2-6-0/)
- [Argo CD advisories](https://github.com/argoproj/argo-cd/security/advisories)
- [Traefik advisories](https://github.com/traefik/traefik/security/advisories)
- [Go release history](https://go.dev/doc/devel/release)
