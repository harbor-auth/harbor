package oidc

import (
	"context"
	"errors"
)

// ErrUserInfoUnavailable collapses inactive, missing and foreign-region users.
var ErrUserInfoUnavailable = errors.New("userinfo: account is unavailable")

// UserInfoClaims are the personal claims Harbor currently supports. Adding a
// scope requires real data, explicit consent wording and disclosure tests.
type UserInfoClaims struct {
	Email         string
	EmailVerified bool
}

// UserInfoSource validates the active regional account on every call. It reads
// and decrypts the verified identifier only when email sharing was authorized.
type UserInfoSource interface {
	UserInfo(ctx context.Context, userID, homeRegion string, shareEmail bool) (UserInfoClaims, error)
}
