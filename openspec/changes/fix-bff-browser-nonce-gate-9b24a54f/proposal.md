---
title: Fail closed when a BFF session has no browser nonce hash
status: complete
created: 2026-08-01
---

# Proposal: Fail closed when a BFF session has no browser nonce hash

## Problem

The browser-nonce gates in `BeginLogin`, `FinishLoginWithParsedData`, and
`GetAuthorizeComplete` only checked the nonce cookie when the session already
contained a `BrowserNonceHash`. A legacy or malformed session with an absent
hash therefore skipped the fixation defense entirely.

## Proposed Solution

Require every session reaching any of the three gates to contain a browser
nonce hash. Reject an absent hash before reading or comparing the cookie, while
preserving the existing cookie parsing and constant-time nonce comparison for
sessions that contain a hash. Keep the `/authorize` flow as the source of the
nonce and stored hash.

## Non-Goals

- Changing nonce generation, cookie attributes, or hash comparison.
- Allowing legacy sessions without a nonce hash to continue login.
- Changing authorization-code issuance or WebAuthn behavior beyond the gate.
