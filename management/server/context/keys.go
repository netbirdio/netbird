package context

import (
	"context"
	"net/netip"

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

type clientIPKey struct{}

// SetClientIP returns a new context carrying the resolved client IP of the request.
func SetClientIP(ctx context.Context, ip netip.Addr) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

// GetClientIP returns the client IP stored in ctx, or false if none is set or it is invalid.
func GetClientIP(ctx context.Context) (netip.Addr, bool) {
	ip, ok := ctx.Value(clientIPKey{}).(netip.Addr)
	return ip, ok && ip.IsValid()
}
