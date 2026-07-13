package auth

import (
	"context"
	"net/netip"
)

// PeerIdentity describes the locally-known facts about a peer reachable on
// the proxy's per-account WireGuard listener. Phase 3 fills PubKey, TunnelIP
// and FQDN from the embedded client's peerstore. UserID, Email and Groups
// stay zero in V1 — full identity still travels through ValidateTunnelPeer.
// Phase V2 will populate them once RemotePeerConfig carries user identity.
type PeerIdentity struct {
	PubKey   string
	TunnelIP netip.Addr
	FQDN     string

	// V2 fields (zero in V1).
	UserID string
	Email  string
	Groups []string
}

// TunnelLookupFunc resolves a tunnel IP to a peer identity using locally
// available peerstore data. ok=false means the IP is not in the calling
// account's roster.
type TunnelLookupFunc func(ip netip.Addr) (PeerIdentity, bool)

type tunnelLookupContextKey struct{}

// WithTunnelLookup attaches a per-account peerstore lookup function to
// the request context. The auth middleware calls this lookup before
// hitting management's ValidateTunnelPeer to short-circuit unknown IPs
// and to skip the RPC for already-cached identities.
func WithTunnelLookup(ctx context.Context, lookup TunnelLookupFunc) context.Context {
	if lookup == nil {
		return ctx
	}
	return context.WithValue(ctx, tunnelLookupContextKey{}, lookup)
}

// TunnelLookupFromContext returns the peerstore lookup attached to ctx,
// or nil when the request did not arrive on a per-account listener.
func TunnelLookupFromContext(ctx context.Context) TunnelLookupFunc {
	v, _ := ctx.Value(tunnelLookupContextKey{}).(TunnelLookupFunc)
	return v
}
