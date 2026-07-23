package oidc

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// RevokeRefreshToken revokes a refresh token per RFC 7009. The method:
//  1. Decodes and hashes the opaque token (plaintext is never stored/logged).
//  2. Looks up the session by token hash.
//  3. Checks client ownership — a client may only revoke tokens it issued.
//  4. Revokes the entire (user, client) session family for theft protection.
//
// Anti-enumeration (RFC 7009 §2.2): this method returns nil for ALL failure
// modes — unknown token, expired token, cross-client token, already-revoked
// token. The caller (oidcapi/revoke.go) always returns HTTP 200 regardless
// of outcome, preventing token-fishing attacks.
//
// Context isolation: uses a detached 10s-bounded context internally so that
// family revocation completes even on client disconnect or SIGINT.
//
//harbor:invariant INV-REVOKE-ANTI-ENUMERATION
func (s *Service) RevokeRefreshToken(ctx context.Context, token, clientID string) error {
	// Step 1: Decode and hash the opaque token.
	raw, err := decodeRefreshToken(token)
	if err != nil {
		// Malformed token — silent no-op (anti-enumeration).
		return nil
	}
	hash := hashRefreshToken(raw)

	// Step 2: Look up the session by token hash.
	session, err := s.sessionStore.GetSessionByTokenHash(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenNotFound) {
			// Unknown or expired token — silent no-op (anti-enumeration).
			return nil
		}
		if errors.Is(err, ErrRefreshTokenRevoked) {
			// Already revoked — silent no-op (anti-enumeration).
			// The session is returned even when revoked, so we can still
			// check client ownership below.
		} else {
			// Transient DB error — log and return nil for anti-enumeration.
			// We do NOT propagate the error as 5xx because RFC 7009 §2.2
			// requires the endpoint to return 200 even on internal failures
			// (the revocation is best-effort from the client's perspective).
			s.logger.ErrorContext(ctx, "revoke: session lookup failed",
				slog.String("client_id", clientID),
				slog.Any("error", err))
			return nil
		}
	}

	// Step 3: Check client ownership — cross-client revocation is silently ignored.
	// This is the RFC 7009 §2.1 rule: "the authorization server [...] validates
	// whether the particular token was issued to the client making the request".
	if session.ClientID != clientID {
		// Cross-client token — silent no-op (anti-enumeration).
		return nil
	}

	// Step 4: Revoke the entire (user, client) session family.
	// This is more aggressive than revoking just the single session, but it
	// matches the theft-signal behavior (signalRefreshReuse) and ensures that
	// a compromised token cannot be used to mint new tokens even if rotated.
	//
	// Use a detached, bounded context so revocation completes even on client
	// disconnect or SIGINT (mirrors signalRefreshReuse behavior).
	revokeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	// Defensive guard: empty UserID would match zero rows and silently suppress
	// the family revoke (same guard as signalRefreshReuse).
	if session.UserID == "" || session.UserID == zeroUUID {
		s.logger.ErrorContext(revokeCtx, "revoke: session has empty/zero UserID — family revoke skipped (latent store bug)",
			slog.String("session_id", session.ID))
		return nil
	}

	if err := s.sessionStore.RevokeSessionsByUserClient(revokeCtx, session.UserID, session.ClientID); err != nil {
		// Log the error but return nil for anti-enumeration.
		s.logger.ErrorContext(revokeCtx, "revoke: family revocation failed",
			slog.String("client_id", session.ClientID),
			slog.Any("error", err))
	}

	return nil
}
