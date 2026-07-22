// Package relay implements Harbor's per-RP email relay service (Hide-My-Email).
// Each user gets a unique, unlinkable relay address per RP that forwards mail
// to their real inbox without exposing their real email address.
//
// Key properties (docs/DESIGN.md §7.5):
//   - Relay tokens are randomly generated, not derived from user_id, so two RPs'
//     addresses for the same user are completely uncorrelated.
//   - Mappings are envelope-encrypted and region-pinned (never cross-region
//     replicated).
//   - State lifecycle: Active (forwarding), Deactivated (hard-bounce kill switch),
//     BYO-domain (user's verified vanity domain).
//   - Deactivation is independent of login grant revocation.
package relay
