---
title: Fail closed when BFF sessions lack a browser nonce hash
status: proposed
created: 2026-08-01
---

# Proposal: Fail closed when BFF sessions lack a browser nonce hash

## Problem

The browser-nonce gates in `BeginLogin`, `FinishLoginWithParsedData`, and
`GetAuthorizeComplete` only validate the nonce when `BrowserNonceHash` is
non-empty. A malformed or legacy session with no stored hash therefore skips
the fixation defense and may advance through the authorization flow.

## Proposed solution

Make each existing gate reject a session whose `BrowserNonceHash` is absent,
then retain the existing nonce-cookie parsing and constant-time hash comparison
for populated hashes. Add focused regression tests for all three checkpoints
and retain coverage showing `/authorize` creates a nonce-bound session that can
complete the normal flow.

## Non-goals

- Changing nonce generation, hashing, cookie attributes, or comparison logic.
- Supporting sessions created without a browser nonce hash.
- Changing user-visible error responses or the BFF flow topology.
