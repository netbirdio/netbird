package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// stubSessionValidator records ValidateTunnelPeer calls and returns the
// pre-canned response. Counts let tests assert RPC traffic.
type stubSessionValidator struct {
	respFn      func(req *proto.ValidateTunnelPeerRequest) *proto.ValidateTunnelPeerResponse
	respErr     error
	tunnelCalls atomic.Int32
}

func (s *stubSessionValidator) ValidateSession(_ context.Context, _ *proto.ValidateSessionRequest, _ ...grpc.CallOption) (*proto.ValidateSessionResponse, error) {
	return &proto.ValidateSessionResponse{Valid: false}, nil
}

func (s *stubSessionValidator) ValidateTunnelPeer(_ context.Context, in *proto.ValidateTunnelPeerRequest, _ ...grpc.CallOption) (*proto.ValidateTunnelPeerResponse, error) {
	s.tunnelCalls.Add(1)
	if s.respErr != nil {
		return nil, s.respErr
	}
	if s.respFn != nil {
		return s.respFn(in), nil
	}
	return &proto.ValidateTunnelPeerResponse{Valid: false}, nil
}

func newTunnelMiddleware(t *testing.T, validator SessionValidator) *Middleware {
	t.Helper()
	mw := NewMiddleware(log.New(), validator, nil)
	require.NoError(t, mw.AddDomain("svc.example", nil, "", 0, "acct-1", "svc-1", nil, false))
	return mw
}

func newTunnelRequest(remoteAddr string) (*httptest.ResponseRecorder, *http.Request) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://svc.example/", nil)
	r.Host = "svc.example"
	r.RemoteAddr = remoteAddr
	return w, r
}

// TestForwardWithTunnelPeer_LocalLookupUnknownIPDeniesFast verifies the
// short-circuit: a tunnel IP not in the account's roster never reaches
// management's ValidateTunnelPeer.
func TestForwardWithTunnelPeer_LocalLookupUnknownIPDeniesFast(t *testing.T) {
	validator := &stubSessionValidator{}
	mw := newTunnelMiddleware(t, validator)

	lookup := TunnelLookupFunc(func(_ netip.Addr) (PeerIdentity, bool) {
		return PeerIdentity{}, false
	})

	w, r := newTunnelRequest("100.64.0.99:55555")
	r = r.WithContext(WithTunnelLookup(r.Context(), lookup))

	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })

	config, _ := mw.getDomainConfig("svc.example")
	handled := mw.forwardWithTunnelPeer(w, r, "svc.example", config, next)

	assert.False(t, handled, "unknown peer must fall through, not forward")
	assert.False(t, called, "next handler must not run for unknown peer")
	assert.Equal(t, int32(0), validator.tunnelCalls.Load(), "ValidateTunnelPeer must be skipped on local-lookup miss")
}

// TestForwardWithTunnelPeer_GroupsPropagateToCapturedData verifies the proxy
// surfaces the calling peer's group memberships from ValidateTunnelPeerResponse
// onto CapturedData so policy-aware middlewares can authorise without an
// extra management round-trip.
func TestForwardWithTunnelPeer_GroupsPropagateToCapturedData(t *testing.T) {
	groups := []string{"engineering", "sre"}
	validator := &stubSessionValidator{
		respFn: func(_ *proto.ValidateTunnelPeerRequest) *proto.ValidateTunnelPeerResponse {
			return &proto.ValidateTunnelPeerResponse{
				Valid:        true,
				SessionToken: "tok",
				UserId:       "user-1",
				PeerGroupIds: groups,
			}
		},
	}
	mw := newTunnelMiddleware(t, validator)

	w, r := newTunnelRequest("100.64.0.10:55555")
	cd := proxy.NewCapturedData("")
	lookup := TunnelLookupFunc(func(_ netip.Addr) (PeerIdentity, bool) {
		return PeerIdentity{}, true
	})
	r = r.WithContext(proxy.WithCapturedData(WithTunnelLookup(r.Context(), lookup), cd))

	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })

	config, _ := mw.getDomainConfig("svc.example")
	handled := mw.forwardWithTunnelPeer(w, r, "svc.example", config, next)

	require.True(t, handled, "valid tunnel-peer response must forward")
	require.True(t, called, "next handler must run")
	assert.Equal(t, "user-1", cd.GetUserID(), "user id must propagate from tunnel-peer response")
	assert.Equal(t, groups, cd.GetUserGroups(), "peer group IDs must propagate from tunnel-peer response")
}

// TestForwardWithTunnelPeer_LocalLookupKnownPeerStillRPCs verifies that a
// known tunnel IP still triggers ValidateTunnelPeer for the user-identity
// tail (UserID + group access). Phase 3 only short-circuits the deny path.
func TestForwardWithTunnelPeer_LocalLookupKnownPeerStillRPCs(t *testing.T) {
	validator := &stubSessionValidator{
		respFn: func(_ *proto.ValidateTunnelPeerRequest) *proto.ValidateTunnelPeerResponse {
			return &proto.ValidateTunnelPeerResponse{Valid: true, SessionToken: "tok", UserId: "user-1"}
		},
	}
	mw := newTunnelMiddleware(t, validator)

	knownIP := netip.MustParseAddr("100.64.0.10")
	lookup := TunnelLookupFunc(func(ip netip.Addr) (PeerIdentity, bool) {
		if ip == knownIP {
			return PeerIdentity{PubKey: "pk", TunnelIP: ip, FQDN: "peer.netbird.cloud"}, true
		}
		return PeerIdentity{}, false
	})

	w, r := newTunnelRequest(knownIP.String() + ":55555")
	r = r.WithContext(WithTunnelLookup(r.Context(), lookup))

	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })

	config, _ := mw.getDomainConfig("svc.example")
	handled := mw.forwardWithTunnelPeer(w, r, "svc.example", config, next)

	assert.True(t, handled, "known peer with valid RPC response must forward")
	assert.True(t, called, "next handler must run on success")
	assert.Equal(t, int32(1), validator.tunnelCalls.Load(), "RPC must run for the user-identity tail when local lookup confirms the peer")
}

// TestForwardWithTunnelPeer_NoLookupRefusesFastPath guards the
// anti-spoof gate: requests that didn't arrive on the per-account
// inbound listener (no TunnelLookup attached) must never reach
// management's ValidateTunnelPeer, even when the source IP looks like
// a tunnel address. A colliding RFC1918 / CGNAT source on the public
// listener would otherwise impersonate a mesh peer.
func TestForwardWithTunnelPeer_NoLookupRefusesFastPath(t *testing.T) {
	validator := &stubSessionValidator{
		respFn: func(_ *proto.ValidateTunnelPeerRequest) *proto.ValidateTunnelPeerResponse {
			return &proto.ValidateTunnelPeerResponse{Valid: true, SessionToken: "tok", UserId: "user-1"}
		},
	}
	mw := newTunnelMiddleware(t, validator)

	w, r := newTunnelRequest("100.64.0.10:55555")
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })

	config, _ := mw.getDomainConfig("svc.example")
	handled := mw.forwardWithTunnelPeer(w, r, "svc.example", config, next)

	assert.False(t, handled, "fast-path must refuse without the inbound marker")
	assert.False(t, called, "next handler must not run")
	assert.Equal(t, int32(0), validator.tunnelCalls.Load(), "ValidateTunnelPeer must not be invoked without the inbound marker")
}

// TestForwardWithTunnelPeer_RPCErrorFallsThrough validates that an RPC
// failure still falls through to the next scheme (no false positive).
func TestForwardWithTunnelPeer_RPCErrorFallsThrough(t *testing.T) {
	validator := &stubSessionValidator{respErr: errors.New("management down")}
	mw := newTunnelMiddleware(t, validator)

	knownIP := netip.MustParseAddr("100.64.0.10")
	lookup := TunnelLookupFunc(func(ip netip.Addr) (PeerIdentity, bool) {
		return PeerIdentity{TunnelIP: ip}, true
	})

	w, r := newTunnelRequest(knownIP.String() + ":55555")
	r = r.WithContext(WithTunnelLookup(r.Context(), lookup))

	config, _ := mw.getDomainConfig("svc.example")
	handled := mw.forwardWithTunnelPeer(w, r, "svc.example", config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	assert.False(t, handled, "RPC error must let the caller try other schemes")
	assert.Equal(t, int32(1), validator.tunnelCalls.Load(), "RPC was attempted exactly once")
}

// TestForwardWithTunnelPeer_CacheReusesPositiveResponse confirms the
// (account, IP, domain) cache prevents repeated RPCs for the same peer.
func TestForwardWithTunnelPeer_CacheReusesPositiveResponse(t *testing.T) {
	validator := &stubSessionValidator{
		respFn: func(_ *proto.ValidateTunnelPeerRequest) *proto.ValidateTunnelPeerResponse {
			return &proto.ValidateTunnelPeerResponse{Valid: true, SessionToken: "tok", UserId: "user-1"}
		},
	}
	mw := newTunnelMiddleware(t, validator)

	lookup := TunnelLookupFunc(func(_ netip.Addr) (PeerIdentity, bool) {
		return PeerIdentity{}, true
	})

	for i := 0; i < 4; i++ {
		w, r := newTunnelRequest("100.64.0.10:55555")
		r = r.WithContext(WithTunnelLookup(r.Context(), lookup))
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
		config, _ := mw.getDomainConfig("svc.example")
		handled := mw.forwardWithTunnelPeer(w, r, "svc.example", config, next)
		require.True(t, handled, "iteration %d should forward", i)
	}

	assert.Equal(t, int32(1), validator.tunnelCalls.Load(), "subsequent forwards must hit the cache, not management")
}

// TestForwardWithTunnelPeer_RoutesAccountIDIntoCacheKey ensures cache keys
// honour account scoping — same tunnel IP on different accounts must not
// collide.
func TestForwardWithTunnelPeer_RoutesAccountIDIntoCacheKey(t *testing.T) {
	validator := &stubSessionValidator{
		respFn: func(req *proto.ValidateTunnelPeerRequest) *proto.ValidateTunnelPeerResponse {
			return &proto.ValidateTunnelPeerResponse{Valid: true, SessionToken: "tok", UserId: "user"}
		},
	}
	mw := NewMiddleware(log.New(), validator, nil)

	require.NoError(t, mw.AddDomain("svc-a.example", nil, "", 0, "acct-a", "svc-a", nil, false))
	require.NoError(t, mw.AddDomain("svc-b.example", nil, "", 0, "acct-b", "svc-b", nil, false))

	// The fast-path requires the inbound-listener marker on the context.
	// The peerstore lookup itself is account-agnostic at this level
	// (one TunnelLookupFunc per account is attached by inbound.go); a
	// trivial "always hit" lookup is enough to exercise the cache-key
	// branch this test covers.
	lookup := TunnelLookupFunc(func(_ netip.Addr) (PeerIdentity, bool) {
		return PeerIdentity{}, true
	})

	for _, host := range []string{"svc-a.example", "svc-b.example"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		r.Host = host
		r.RemoteAddr = "100.64.0.10:55555"
		r = r.WithContext(WithTunnelLookup(r.Context(), lookup))
		config, _ := mw.getDomainConfig(host)
		handled := mw.forwardWithTunnelPeer(w, r, host, config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		require.True(t, handled, "host %s should forward", host)
	}

	assert.Equal(t, int32(2), validator.tunnelCalls.Load(), "cache must not collide across accounts even when tunnel IPs match")
}

// TestForwardWithTunnelPeer_LocalLookupShortCircuitDoesNotPopulateCache
// guarantees that the deny-fast path leaves the cache untouched, so a
// subsequent request from the same IP after the peerstore catches up
// goes through the normal RPC flow.
func TestForwardWithTunnelPeer_LocalLookupShortCircuitDoesNotPopulateCache(t *testing.T) {
	validator := &stubSessionValidator{
		respFn: func(_ *proto.ValidateTunnelPeerRequest) *proto.ValidateTunnelPeerResponse {
			return &proto.ValidateTunnelPeerResponse{Valid: true, SessionToken: "tok"}
		},
	}
	mw := newTunnelMiddleware(t, validator)

	knownIP := netip.MustParseAddr("100.64.0.10")
	known := false
	lookup := TunnelLookupFunc(func(ip netip.Addr) (PeerIdentity, bool) {
		if known && ip == knownIP {
			return PeerIdentity{TunnelIP: ip}, true
		}
		return PeerIdentity{}, false
	})

	doRequest := func() bool {
		w, r := newTunnelRequest(knownIP.String() + ":55555")
		r = r.WithContext(WithTunnelLookup(r.Context(), lookup))
		config, _ := mw.getDomainConfig("svc.example")
		return mw.forwardWithTunnelPeer(w, r, "svc.example", config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	}

	require.False(t, doRequest(), "first request must short-circuit")
	require.Equal(t, int32(0), validator.tunnelCalls.Load(), "short-circuit must not populate the cache")

	known = true
	require.True(t, doRequest(), "second request with peer in roster must forward via RPC")
	assert.Equal(t, int32(1), validator.tunnelCalls.Load(), "RPC runs once after peerstore catches up")
}

func TestPrivateService_FailsClosedOnTunnelPeerFailure(t *testing.T) {
	mw := NewMiddleware(log.New(), nil, nil)
	require.NoError(t, mw.AddDomain("private.svc", nil, "", 0, "acct-1", "svc-1", nil, true))

	called := false
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://private.svc/", nil)
	req.Host = "private.svc"
	req.RemoteAddr = "100.64.0.10:55555"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, called)
}

func TestPrivateService_ForwardsOnTunnelPeerSuccess(t *testing.T) {
	validator := &stubSessionValidator{
		respFn: func(_ *proto.ValidateTunnelPeerRequest) *proto.ValidateTunnelPeerResponse {
			return &proto.ValidateTunnelPeerResponse{
				Valid:        true,
				SessionToken: "tok",
				UserId:       "user-1",
			}
		},
	}
	mw := NewMiddleware(log.New(), validator, nil)
	require.NoError(t, mw.AddDomain("private.svc", nil, "", 0, "acct-1", "svc-1", nil, true))

	called := false
	handler := mw.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	// Per-account inbound listener attaches WithTunnelLookup; without it
	// forwardWithTunnelPeer refuses to take the fast-path. Mirror the
	// real flow so this test exercises the post-gating success branch.
	lookup := TunnelLookupFunc(func(_ netip.Addr) (PeerIdentity, bool) {
		return PeerIdentity{}, true
	})

	req := httptest.NewRequest(http.MethodGet, "https://private.svc/", nil)
	req.Host = "private.svc"
	req.RemoteAddr = "100.64.0.10:55555"
	req = req.WithContext(WithTunnelLookup(req.Context(), lookup))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, called)
}
