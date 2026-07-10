> **DESIGN §2.4** · [↑ DESIGN index](../../DESIGN.md) · prev: [trust-model](trust-model.md)

# Privacy Positioning: Google vs Apple vs Harbor

Harbor's north star for *user-facing* privacy UX is **Sign in with Apple**; our differentiator is extending that same protection to cover **the provider itself** and adding **sovereignty + openness** that neither Google nor Apple offers.

**The one-liner:** *Apple protects you from the apps. Harbor protects you from the apps **and from Harbor itself** — and doesn't lock you into a hardware ecosystem to get it.*

## 2.4.1 The philosophical split

- **Google** monetizes identity: the login is a convenience that also feeds an advertising profile. Your **real Gmail address** is the durable cross-app key.
- **Apple** monetizes hardware/services and uses privacy as a *differentiator*: it deliberately severs the cross-app identifier (relay email, per-team `sub`, one-time data release). **But** Apple is still a central party that *sees* your logins — it just promises not to exploit them, and you're tied to the Apple ecosystem.
- **Harbor** monetizes the auth service directly (no ads, ever) and makes "we can't build a profile" a **technical property** (PPID, data-minimized logs, per-region residency, open source + audits), not merely a policy promise.

## 2.4.2 The two Apple privacy features worth borrowing

1. **Private email relay** (`@privaterelay.appleid.com`): each app gets a *unique, per-app* random relay address that forwards to the user's real inbox; the user can deactivate any relay address as a per-app kill switch. Google has **no equivalent** — it hands apps the real Gmail address every time.
2. **Minimal, one-time data release**: Apple shares only name + email, and only on the *first* authorization; apps must capture it then. Google returns profile info (per requested scope) on **every** login.

## 2.4.3 Technical differences at a glance

| Dimension | Sign in with Apple | Sign in with Google |
|---|---|---|
| Protocol | OIDC (OAuth 2.0) | OIDC (OAuth 2.0) |
| ID token | **JWT** (RS256) | **JWT** (RS256) |
| Client authentication | App generates a **signed JWT client secret** from a `.p8` key (ES256), ≤6 months | Static `client_secret` string |
| `sub` (subject) | Stable **per developer team**, opaque | Stable Google account id, paired with real email |
| Data returned | Name + email **once**; email may be a relay | Profile info per scope, **every** login |
| "Is it a relay?" signal | `is_private_email` claim | N/A |
| Provider's own use of the login graph | Sees it; promises not to exploit | Sees it **and actively uses it** |

## 2.4.4 The privacy spectrum — where Harbor sits

| Property | Google | Apple | **Harbor (target)** |
|---|---|---|---|
| Per-app email masking | ❌ real email | ✅ relay email | ✅ relay **+ bring-your-own-domain** |
| Cross-app correlation **by RPs** | ❌ easy (real email) | ✅ blocked (per-team `sub`) | ✅ blocked (**PPID**, per-RP) |
| Cross-app correlation **by the provider** | ❌ Google does it | ⚠️ Apple *could* | ✅ **designed out** (PPID, minimal logs, verifiable) |
| Minimal data sharing | ❌ scope-hungry | ✅ name+email once | ✅ share *nothing* by default; selective-disclosure claims opt-in |
| Provider sees your login graph | ✅ yes & uses it | ✅ yes (promises not to) | ⚖️ minimized & technically constrained (sovereignty) |
| Ecosystem lock-in | Google account | Apple hardware | ✅ **none** — open, portable, standards-based |
| Data sovereignty / region pinning | Global | Global | ✅ **per-jurisdiction**, data never leaves region |
| Open / auditable | ❌ closed | ❌ closed | ✅ **open-source + third-party audited** |

## 2.4.5 What we borrow, and where we deliberately go further

**Borrow from Apple:** (1) per-RP email relay (with optional bring-your-own-domain), (2) per-RP opaque identifier — our **PPID** (§3.2), (3) default-to-nothing / selective data release, (4) per-app kill switches in the dashboard.

**Beat Apple:** Apple's `sub` is stable **per developer team**, so a company with many apps *can* correlate you across all of them. Harbor's **PPID is per-RP registration**, tightening that boundary — and our data-minimization + sovereignty + open audit aim to make "we can't build a profile" a *technical* guarantee rather than a policy promise.

> **Note on the ID-token JWT:** all three providers use a **JWT for the ID token**, consumed by the RP exactly **once** at login (verified offline via JWKS), after which the RP creates its own session. Google's *access token*, by contrast, is **opaque** and server-side (instantly revocable, since Google is its own resource server). Harbor's token choices and why they differ are detailed in §3.5.
