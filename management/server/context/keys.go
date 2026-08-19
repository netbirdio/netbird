package context

import (
	"context"

	nbcontext "github.com/netbirdio/netbird/shared/context"
)

const (
	RequestIDKey = nbcontext.RequestIDKey
	AccountIDKey = nbcontext.AccountIDKey
	RoleKey      = nbcontext.RoleKey
	UserIDKey    = nbcontext.UserIDKey
	PeerIDKey    = nbcontext.PeerIDKey
	UserAgentKey = nbcontext.UserAgentKey
)

// RoleFromContext returns the role stored in ctx, or empty string and false if absent.
func RoleFromContext(ctx context.Context) (string, bool) {
	role, ok := ctx.Value(RoleKey).(string)
	return role, ok
}

// WithRole returns a new context carrying the given role.
func WithRole(ctx context.Context, role string) context.Context {
	//nolint
	return context.WithValue(ctx, RoleKey, role)
}
