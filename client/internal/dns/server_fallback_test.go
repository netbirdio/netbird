package dns

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
)

// refreshingHostManager stands in for a desktop host manager that snapshots
// the OS resolvers: current and captureErr are what the OS reports now,
// snapshot is what the manager hands out as fallback until it is replaced.
type refreshingHostManager struct {
	mockHostConfigurator
	current    []netip.Addr
	captureErr error
	snapshot   []netip.Addr
}

func (r *refreshingHostManager) getOriginalNameservers() []netip.Addr {
	return r.snapshot
}

func (r *refreshingHostManager) captureOriginalNameservers() ([]netip.Addr, error) {
	return r.current, r.captureErr
}

func (r *refreshingHostManager) setOriginalNameservers(nameservers []netip.Addr) {
	r.snapshot = nameservers
}

func fallbackUpstreams(t *testing.T, s *DefaultServer) []netip.AddrPort {
	t.Helper()
	require.NotNil(t, s.fallbackHandler, "a fallback handler must be registered")
	resolver, ok := s.fallbackHandler.(*upstreamResolver)
	require.True(t, ok, "fallback handler must be an upstream resolver, got %T", s.fallbackHandler)
	var out []netip.AddrPort
	for _, race := range resolver.upstreamServers {
		out = append(out, race...)
	}
	return out
}

// newFallbackServer returns a server whose fallback is registered on oldNS,
// the resolver the host had when the client started.
func newFallbackServer(t *testing.T, oldNS netip.Addr) (*DefaultServer, *refreshingHostManager) {
	t.Helper()
	hostManager := &refreshingHostManager{current: []netip.Addr{oldNS}, snapshot: []netip.Addr{oldNS}}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	server := &DefaultServer{
		ctx:            ctx,
		handlerChain:   NewHandlerChain(),
		hostManager:    hostManager,
		service:        &mockService{},
		wgInterface:    &mocWGIface{},
		statusRecorder: peer.NewRecorder("test"),
		hostsDNSHolder: newHostsDNSHolder(),
	}

	server.mux.Lock()
	server.registerFallback()
	server.mux.Unlock()
	require.Equal(t, []netip.AddrPort{netip.AddrPortFrom(oldNS, DefaultPort)}, fallbackUpstreams(t, server),
		"fallback must start on the resolver of the first network")
	return server, hostManager
}

func TestRefreshHostFallback_FollowsHostResolvers(t *testing.T) {
	oldNS := netip.MustParseAddr("10.10.10.10")
	newNS := netip.MustParseAddr("192.168.1.1")
	server, hostManager := newFallbackServer(t, oldNS)

	// The host moves to another network whose DHCP hands out another resolver.
	hostManager.current = []netip.Addr{newNS}
	server.RefreshHostFallback()

	assert.Equal(t, []netip.AddrPort{netip.AddrPortFrom(newNS, DefaultPort)}, fallbackUpstreams(t, server),
		"fallback must follow the host to the resolver of the new network")
}

func TestRefreshHostFallback_KeepsPreviousWhenCaptureIsUnusable(t *testing.T) {
	oldNS := netip.MustParseAddr("10.10.10.10")
	tests := []struct {
		name    string
		current []netip.Addr
		err     error
	}{
		// The new link has not published its DNS yet.
		{name: "empty capture"},
		// systemd-resolved or NetworkManager did not answer.
		{name: "failed capture", err: errors.New("dbus unavailable")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, hostManager := newFallbackServer(t, oldNS)
			before := server.fallbackHandler

			hostManager.current, hostManager.captureErr = tt.current, tt.err
			server.RefreshHostFallback()

			assert.Same(t, before, server.fallbackHandler, "an unusable capture must leave the fallback handler in place")
			assert.Equal(t, []netip.Addr{oldNS}, hostManager.snapshot, "an unusable capture must keep the previous snapshot")
		})
	}
}

func TestRefreshHostFallback_KeepsHandlerWhenResolversAreUnchanged(t *testing.T) {
	// A dock plugged in on the same LAN moves the default route but keeps the resolver.
	server, _ := newFallbackServer(t, netip.MustParseAddr("10.10.10.10"))
	before := server.fallbackHandler

	server.RefreshHostFallback()

	assert.Same(t, before, server.fallbackHandler, "unchanged resolvers must not replace the fallback handler and drop its in-flight queries")
}

func TestRefreshHostFallback_SkipsManagerWithoutSnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	server := &DefaultServer{
		ctx:          ctx,
		handlerChain: NewHandlerChain(),
		hostManager:  &noopHostConfigurator{},
	}

	server.RefreshHostFallback()

	assert.Nil(t, server.fallbackHandler, "a manager without a snapshot must not register a fallback")
}
