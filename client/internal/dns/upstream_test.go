package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/dns/test"
)

func TestUpstreamResolver_ServeDNS(t *testing.T) {

	testCases := []struct {
		name                string
		inputMSG            *dns.Msg
		responseShouldBeNil bool
		InputServers        []string
		timeout             time.Duration
		cancelCTX           bool
		expectedAnswer      string
		acceptNXDomain      bool
	}{
		{
			name:           "Should Resolve A Record",
			inputMSG:       new(dns.Msg).SetQuestion("one.one.one.one.", dns.TypeA),
			InputServers:   []string{"8.8.8.8:53", "8.8.4.4:53"},
			timeout:        UpstreamTimeout,
			expectedAnswer: "1.1.1.1",
		},
		{
			name:           "Should Resolve If First Upstream Times Out",
			inputMSG:       new(dns.Msg).SetQuestion("one.one.one.one.", dns.TypeA),
			InputServers:   []string{"8.0.0.0:53", "8.8.4.4:53"},
			timeout:        2 * time.Second,
			expectedAnswer: "1.1.1.1",
		},
		{
			name:           "Should Not Resolve If Can't Connect To Both Servers",
			inputMSG:       new(dns.Msg).SetQuestion("one.one.one.one.", dns.TypeA),
			InputServers:   []string{"8.0.0.0:53", "8.0.0.1:53"},
			timeout:        200 * time.Millisecond,
			acceptNXDomain: true,
		},
		{
			name:                "Should Not Resolve If Parent Context Is Canceled",
			inputMSG:            new(dns.Msg).SetQuestion("one.one.one.one.", dns.TypeA),
			InputServers:        []string{"8.0.0.0:53", "8.8.4.4:53"},
			cancelCTX:           true,
			timeout:             UpstreamTimeout,
			responseShouldBeNil: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.TODO())
			resolver, _ := newUpstreamResolver(ctx, &mockNetstackProvider{}, nil, nil, ".")
			// Convert test servers to netip.AddrPort
			var servers []netip.AddrPort
			for _, server := range testCase.InputServers {
				if addrPort, err := netip.ParseAddrPort(server); err == nil {
					servers = append(servers, netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()))
				}
			}
			resolver.upstreamServers = servers
			resolver.upstreamTimeout = testCase.timeout
			if testCase.cancelCTX {
				cancel()
			} else {
				defer cancel()
			}

			var responseMSG *dns.Msg
			responseWriter := &test.MockResponseWriter{
				WriteMsgFunc: func(m *dns.Msg) error {
					responseMSG = m
					return nil
				},
			}

			resolver.ServeDNS(responseWriter, testCase.inputMSG)

			if responseMSG == nil {
				if testCase.responseShouldBeNil {
					return
				}
				t.Fatalf("should write a response message")
			}

			if testCase.acceptNXDomain && responseMSG.Rcode == dns.RcodeNameError {
				return
			}

			if testCase.expectedAnswer != "" {
				foundAnswer := false
				for _, answer := range responseMSG.Answer {
					if strings.Contains(answer.String(), testCase.expectedAnswer) {
						foundAnswer = true
						break
					}
				}

				if !foundAnswer {
					t.Errorf("couldn't find the required answer, %s, in the dns response", testCase.expectedAnswer)
				}
			}
		})
	}
}

type mockNetstackProvider struct{}

func (m *mockNetstackProvider) Name() string                      { return "mock" }
func (m *mockNetstackProvider) Address() wgaddr.Address           { return wgaddr.Address{} }
func (m *mockNetstackProvider) ToInterface() *net.Interface       { return nil }
func (m *mockNetstackProvider) IsUserspaceBind() bool             { return false }
func (m *mockNetstackProvider) GetFilter() device.PacketFilter    { return nil }
func (m *mockNetstackProvider) GetDevice() *device.FilteredDevice { return nil }
func (m *mockNetstackProvider) GetNet() *netstack.Net             { return nil }
func (m *mockNetstackProvider) GetInterfaceGUIDString() (string, error) {
	return "", nil
}

type mockUpstreamResolver struct {
	r   *dns.Msg
	rtt time.Duration
	err error
}

// exchange mock implementation of exchange from upstreamResolver
func (c mockUpstreamResolver) exchange(_ context.Context, _ string, _ *dns.Msg) (*dns.Msg, time.Duration, error) {
	return c.r, c.rtt, c.err
}

type mockUpstreamResponse struct {
	msg *dns.Msg
	err error
}

type mockUpstreamResolverPerServer struct {
	responses map[string]mockUpstreamResponse
	rtt       time.Duration
}

func (c mockUpstreamResolverPerServer) exchange(_ context.Context, upstream string, _ *dns.Msg) (*dns.Msg, time.Duration, error) {
	if r, ok := c.responses[upstream]; ok {
		return r.msg, c.rtt, r.err
	}
	return nil, c.rtt, fmt.Errorf("no mock response for %s", upstream)
}

func TestUpstreamResolver_DeactivationReactivation(t *testing.T) {
	mockClient := &mockUpstreamResolver{
		err: dns.ErrTime,
		r:   new(dns.Msg),
		rtt: time.Millisecond,
	}

	resolver := &upstreamResolverBase{
		ctx:              context.TODO(),
		upstreamClient:   mockClient,
		upstreamTimeout:  UpstreamTimeout,
		reactivatePeriod: time.Microsecond * 100,
	}
	addrPort, _ := netip.ParseAddrPort("0.0.0.0:1") // Use valid port for parsing, test will still fail on connection
	resolver.upstreamServers = []netip.AddrPort{netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())}

	failed := false
	resolver.deactivate = func(error) {
		failed = true
		// After deactivation, make the mock client work again
		mockClient.err = nil
	}

	reactivated := false
	resolver.reactivate = func() {
		reactivated = true
	}

	resolver.ProbeAvailability()

	if !failed {
		t.Errorf("expected that resolving was deactivated")
		return
	}

	if !resolver.disabled {
		t.Errorf("resolver should be Disabled")
		return
	}

	time.Sleep(time.Millisecond * 200)

	if !reactivated {
		t.Errorf("expected that resolving was reactivated")
		return
	}

	if resolver.disabled {
		t.Errorf("should be enabled")
	}
}

func TestUpstreamResolver_Failover(t *testing.T) {
	upstream1 := netip.MustParseAddrPort("192.0.2.1:53")
	upstream2 := netip.MustParseAddrPort("192.0.2.2:53")

	successAnswer := "192.0.2.100"
	timeoutErr := &net.OpError{Op: "read", Err: fmt.Errorf("i/o timeout")}

	testCases := []struct {
		name            string
		upstream1       mockUpstreamResponse
		upstream2       mockUpstreamResponse
		expectedRcode   int
		expectAnswer    bool
		expectTrySecond bool
	}{
		{
			name:            "success on first upstream",
			upstream1:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeSuccess, successAnswer)},
			upstream2:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeSuccess, successAnswer)},
			expectedRcode:   dns.RcodeSuccess,
			expectAnswer:    true,
			expectTrySecond: false,
		},
		{
			name:            "SERVFAIL from first should try second",
			upstream1:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeServerFailure, "")},
			upstream2:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeSuccess, successAnswer)},
			expectedRcode:   dns.RcodeSuccess,
			expectAnswer:    true,
			expectTrySecond: true,
		},
		{
			name:            "REFUSED from first should try second",
			upstream1:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeRefused, "")},
			upstream2:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeSuccess, successAnswer)},
			expectedRcode:   dns.RcodeSuccess,
			expectAnswer:    true,
			expectTrySecond: true,
		},
		{
			name:            "NXDOMAIN from first should NOT try second",
			upstream1:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeNameError, "")},
			upstream2:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeSuccess, successAnswer)},
			expectedRcode:   dns.RcodeNameError,
			expectAnswer:    false,
			expectTrySecond: false,
		},
		{
			name:            "timeout from first should try second",
			upstream1:       mockUpstreamResponse{err: timeoutErr},
			upstream2:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeSuccess, successAnswer)},
			expectedRcode:   dns.RcodeSuccess,
			expectAnswer:    true,
			expectTrySecond: true,
		},
		{
			name:            "no response from first should try second",
			upstream1:       mockUpstreamResponse{msg: nil},
			upstream2:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeSuccess, successAnswer)},
			expectedRcode:   dns.RcodeSuccess,
			expectAnswer:    true,
			expectTrySecond: true,
		},
		{
			name:            "both upstreams return SERVFAIL",
			upstream1:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeServerFailure, "")},
			upstream2:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeServerFailure, "")},
			expectedRcode:   dns.RcodeServerFailure,
			expectAnswer:    false,
			expectTrySecond: true,
		},
		{
			name:            "both upstreams timeout",
			upstream1:       mockUpstreamResponse{err: timeoutErr},
			upstream2:       mockUpstreamResponse{err: timeoutErr},
			expectedRcode:   dns.RcodeServerFailure,
			expectAnswer:    false,
			expectTrySecond: true,
		},
		{
			name:            "first SERVFAIL then timeout",
			upstream1:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeServerFailure, "")},
			upstream2:       mockUpstreamResponse{err: timeoutErr},
			expectedRcode:   dns.RcodeServerFailure,
			expectAnswer:    false,
			expectTrySecond: true,
		},
		{
			name:            "first timeout then SERVFAIL",
			upstream1:       mockUpstreamResponse{err: timeoutErr},
			upstream2:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeServerFailure, "")},
			expectedRcode:   dns.RcodeServerFailure,
			expectAnswer:    false,
			expectTrySecond: true,
		},
		{
			name:            "first REFUSED then SERVFAIL",
			upstream1:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeRefused, "")},
			upstream2:       mockUpstreamResponse{msg: buildMockResponse(dns.RcodeServerFailure, "")},
			expectedRcode:   dns.RcodeServerFailure,
			expectAnswer:    false,
			expectTrySecond: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var queriedUpstreams []string
			mockClient := &mockUpstreamResolverPerServer{
				responses: map[string]mockUpstreamResponse{
					upstream1.String(): tc.upstream1,
					upstream2.String(): tc.upstream2,
				},
				rtt: time.Millisecond,
			}

			trackingClient := &trackingMockClient{
				inner:            mockClient,
				queriedUpstreams: &queriedUpstreams,
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			resolver := &upstreamResolverBase{
				ctx:             ctx,
				upstreamClient:  trackingClient,
				upstreamServers: []netip.AddrPort{upstream1, upstream2},
				upstreamTimeout: UpstreamTimeout,
			}

			var responseMSG *dns.Msg
			responseWriter := &test.MockResponseWriter{
				WriteMsgFunc: func(m *dns.Msg) error {
					responseMSG = m
					return nil
				},
			}

			inputMSG := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
			resolver.ServeDNS(responseWriter, inputMSG)

			require.NotNil(t, responseMSG, "should write a response")
			assert.Equal(t, tc.expectedRcode, responseMSG.Rcode, "unexpected rcode")

			if tc.expectAnswer {
				require.NotEmpty(t, responseMSG.Answer, "expected answer records")
				assert.Contains(t, responseMSG.Answer[0].String(), successAnswer)
			}

			if tc.expectTrySecond {
				assert.Len(t, queriedUpstreams, 2, "should have tried both upstreams")
				assert.Equal(t, upstream1.String(), queriedUpstreams[0])
				assert.Equal(t, upstream2.String(), queriedUpstreams[1])
			} else {
				assert.Len(t, queriedUpstreams, 1, "should have only tried first upstream")
				assert.Equal(t, upstream1.String(), queriedUpstreams[0])
			}
		})
	}
}

type trackingMockClient struct {
	inner            *mockUpstreamResolverPerServer
	queriedUpstreams *[]string
}

func (t *trackingMockClient) exchange(ctx context.Context, upstream string, r *dns.Msg) (*dns.Msg, time.Duration, error) {
	*t.queriedUpstreams = append(*t.queriedUpstreams, upstream)
	return t.inner.exchange(ctx, upstream, r)
}

func buildMockResponse(rcode int, answer string) *dns.Msg {
	m := new(dns.Msg)
	m.Response = true
	m.Rcode = rcode

	if rcode == dns.RcodeSuccess && answer != "" {
		m.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP(answer),
			},
		}
	}
	return m
}

func TestUpstreamResolver_SingleUpstreamFailure(t *testing.T) {
	upstream := netip.MustParseAddrPort("192.0.2.1:53")

	mockClient := &mockUpstreamResolverPerServer{
		responses: map[string]mockUpstreamResponse{
			upstream.String(): {msg: buildMockResponse(dns.RcodeServerFailure, "")},
		},
		rtt: time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver := &upstreamResolverBase{
		ctx:             ctx,
		upstreamClient:  mockClient,
		upstreamServers: []netip.AddrPort{upstream},
		upstreamTimeout: UpstreamTimeout,
	}

	var responseMSG *dns.Msg
	responseWriter := &test.MockResponseWriter{
		WriteMsgFunc: func(m *dns.Msg) error {
			responseMSG = m
			return nil
		},
	}

	inputMSG := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	resolver.ServeDNS(responseWriter, inputMSG)

	require.NotNil(t, responseMSG, "should write a response")
	assert.Equal(t, dns.RcodeServerFailure, responseMSG.Rcode, "single upstream SERVFAIL should return SERVFAIL")
}

func TestFormatFailures(t *testing.T) {
	testCases := []struct {
		name     string
		failures []upstreamFailure
		expected string
	}{
		{
			name:     "empty slice",
			failures: []upstreamFailure{},
			expected: "",
		},
		{
			name: "single failure",
			failures: []upstreamFailure{
				{upstream: netip.MustParseAddrPort("8.8.8.8:53"), reason: "SERVFAIL"},
			},
			expected: "8.8.8.8:53=SERVFAIL",
		},
		{
			name: "multiple failures",
			failures: []upstreamFailure{
				{upstream: netip.MustParseAddrPort("8.8.8.8:53"), reason: "SERVFAIL"},
				{upstream: netip.MustParseAddrPort("8.8.4.4:53"), reason: "timeout after 2s"},
			},
			expected: "8.8.8.8:53=SERVFAIL, 8.8.4.4:53=timeout after 2s",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := formatFailures(tc.failures)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestIsNetBirdOverlayAddr verifies that the CGNAT range check correctly
// identifies NetBird overlay addresses vs regular addresses.
func TestIsNetBirdOverlayAddr(t *testing.T) {
	testCases := []struct {
		name     string
		addr     string
		expected bool
	}{
		{
			name:     "NetBird overlay address at start of range",
			addr:     "100.64.0.1:53",
			expected: true,
		},
		{
			name:     "NetBird overlay address mid-range",
			addr:     "100.110.145.54:53",
			expected: true,
		},
		{
			name:     "NetBird overlay address end of range",
			addr:     "100.127.255.254:53",
			expected: true,
		},
		{
			name:     "LAN address",
			addr:     "192.168.1.5:53",
			expected: false,
		},
		{
			name:     "LAN address secondary DC",
			addr:     "192.168.1.30:53",
			expected: false,
		},
		{
			name:     "public DNS address",
			addr:     "8.8.8.8:53",
			expected: false,
		},
		{
			name:     "address just below CGNAT range",
			addr:     "100.63.255.255:53",
			expected: false,
		},
		{
			name:     "address just above CGNAT range",
			addr:     "100.128.0.0:53",
			expected: false,
		},
		{
			name:     "loopback address",
			addr:     "127.0.0.1:53",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addr := netip.MustParseAddrPort(tc.addr)
			result := isNetBirdOverlayAddr(addr)
			assert.Equal(t, tc.expected, result, "isNetBirdOverlayAddr(%s)", tc.addr)
		})
	}
}

// TestProbeAvailability_SkipsOverlayAddresses verifies that ProbeAvailability
// does not probe or deactivate when all nameservers are NetBird overlay
// addresses (100.64.0.0/10). These are unreachable at engine startup because
// the WireGuard tunnel has not yet been established.
func TestProbeAvailability_SkipsOverlayAddresses(t *testing.T) {
	overlayUpstream := netip.MustParseAddrPort("100.110.145.54:53")

	probed := false
	mockClient := &mockUpstreamResolverPerServer{
		responses: map[string]mockUpstreamResponse{
			overlayUpstream.String(): {err: fmt.Errorf("tunnel not up")},
		},
		rtt: time.Millisecond,
	}

	trackingClient := &trackingUpstreamClient{
		inner:  mockClient,
		probed: &probed,
	}

	deactivated := false
	resolver := &upstreamResolverBase{
		ctx:             context.Background(),
		upstreamClient:  trackingClient,
		upstreamServers: []netip.AddrPort{overlayUpstream},
		upstreamTimeout: UpstreamTimeout,
		deactivate:      func(error) { deactivated = true },
		reactivate:      func() {},
	}

	resolver.ProbeAvailability()

	assert.False(t, probed, "overlay address should not have been probed")
	assert.False(t, deactivated, "resolver should not have been deactivated for overlay address")
	assert.False(t, resolver.disabled, "resolver should not be disabled")
}

// TestProbeAvailability_ProbesLANAddresses verifies that ProbeAvailability
// still probes non-overlay (LAN/public) nameservers normally.
func TestProbeAvailability_ProbesLANAddresses(t *testing.T) {
	lanUpstream := netip.MustParseAddrPort("192.168.1.5:53")

	probed := false
	mockClient := &mockUpstreamResolverPerServer{
		responses: map[string]mockUpstreamResponse{
			lanUpstream.String(): {err: fmt.Errorf("connection refused")},
		},
		rtt: time.Millisecond,
	}

	trackingClient := &trackingUpstreamClient{
		inner:  mockClient,
		probed: &probed,
	}

	deactivated := false
	resolver := &upstreamResolverBase{
		ctx:             context.Background(),
		upstreamClient:  trackingClient,
		upstreamServers: []netip.AddrPort{lanUpstream},
		upstreamTimeout: UpstreamTimeout,
		deactivate:      func(error) { deactivated = true },
		reactivate:      func() {},
	}

	resolver.ProbeAvailability()

	assert.True(t, probed, "LAN address should have been probed")
	assert.True(t, deactivated, "resolver should have been deactivated when LAN probe fails")
}

// TestProbeAvailability_MixedOverlayAndLAN verifies that when a nameserver
// group contains both overlay and LAN addresses, the overlay is skipped but
// the LAN address is still probed. A successful LAN probe prevents deactivation.
func TestProbeAvailability_MixedOverlayAndLAN(t *testing.T) {
	overlayUpstream := netip.MustParseAddrPort("100.110.145.54:53")
	lanUpstream := netip.MustParseAddrPort("192.168.1.5:53")

	probedAddrs := make(map[string]bool)
	mockClient := &mockUpstreamResolverPerServer{
		responses: map[string]mockUpstreamResponse{
			overlayUpstream.String(): {err: fmt.Errorf("tunnel not up")},
			lanUpstream.String():     {msg: &dns.Msg{MsgHdr: dns.MsgHdr{Response: true}}},
		},
		rtt: time.Millisecond,
	}

	trackingClient := &trackingUpstreamClientPerAddr{
		inner:       mockClient,
		probedAddrs: probedAddrs,
	}

	deactivated := false
	resolver := &upstreamResolverBase{
		ctx:             context.Background(),
		upstreamClient:  trackingClient,
		upstreamServers: []netip.AddrPort{overlayUpstream, lanUpstream},
		upstreamTimeout: UpstreamTimeout,
		deactivate:      func(error) { deactivated = true },
		reactivate:      func() {},
	}

	resolver.ProbeAvailability()

	assert.False(t, probedAddrs[overlayUpstream.String()], "overlay address should not have been probed")
	assert.True(t, probedAddrs[lanUpstream.String()], "LAN address should have been probed")
	assert.False(t, deactivated, "resolver should not be deactivated when LAN probe succeeds")
}

// TestProbeAvailability_OnlyOverlay_NoDeactivation verifies that a nameserver
// group containing only overlay addresses is never deactivated. The probedAny
// flag ensures we return early without triggering the disable path.
func TestProbeAvailability_OnlyOverlay_NoDeactivation(t *testing.T) {
	overlay1 := netip.MustParseAddrPort("100.110.145.54:53")
	overlay2 := netip.MustParseAddrPort("100.64.0.1:53")

	deactivated := false
	resolver := &upstreamResolverBase{
		ctx: context.Background(),
		// upstreamClient intentionally nil — it must never be called
		upstreamServers: []netip.AddrPort{overlay1, overlay2},
		upstreamTimeout: UpstreamTimeout,
		deactivate:      func(error) { deactivated = true },
		reactivate:      func() {},
	}

	// Should not panic (nil client never called) and should not deactivate
	require.NotPanics(t, func() {
		resolver.ProbeAvailability()
	})

	assert.False(t, deactivated, "resolver should not be deactivated for overlay-only nameserver group")
	assert.False(t, resolver.disabled, "resolver should not be disabled")
}

// TestProbeAvailability_MixedOverlayAndLAN_LANFails verifies that when a
// nameserver group contains both overlay and LAN addresses, and the LAN probe
// fails, the resolver is deactivated. The overlay skip must not mask a genuine
// LAN failure.
func TestProbeAvailability_MixedOverlayAndLAN_LANFails(t *testing.T) {
	overlayUpstream := netip.MustParseAddrPort("100.110.145.54:53")
	lanUpstream := netip.MustParseAddrPort("192.168.1.5:53")

	mockClient := &mockUpstreamResolverPerServer{
		responses: map[string]mockUpstreamResponse{
			overlayUpstream.String(): {err: fmt.Errorf("tunnel not up")},
			lanUpstream.String():     {err: fmt.Errorf("connection refused")},
		},
		rtt: time.Millisecond,
	}

	deactivated := false
	resolver := &upstreamResolverBase{
		ctx:             context.Background(),
		upstreamClient:  mockClient,
		upstreamServers: []netip.AddrPort{overlayUpstream, lanUpstream},
		upstreamTimeout: UpstreamTimeout,
		deactivate:      func(error) { deactivated = true },
		reactivate:      func() {},
	}

	resolver.ProbeAvailability()

	assert.True(t, deactivated, "resolver should be deactivated when LAN probe fails even with overlay present")
}

// trackingUpstreamClient records whether any probe was attempted, regardless of address.
type trackingUpstreamClient struct {
	inner  *mockUpstreamResolverPerServer
	probed *bool
}

func (t *trackingUpstreamClient) exchange(ctx context.Context, upstream string, r *dns.Msg) (*dns.Msg, time.Duration, error) {
	*t.probed = true
	return t.inner.exchange(ctx, upstream, r)
}

// trackingUpstreamClientPerAddr records which addresses were probed.
type trackingUpstreamClientPerAddr struct {
	inner       *mockUpstreamResolverPerServer
	probedAddrs map[string]bool
}

func (t *trackingUpstreamClientPerAddr) exchange(ctx context.Context, upstream string, r *dns.Msg) (*dns.Msg, time.Duration, error) {
	t.probedAddrs[upstream] = true
	return t.inner.exchange(ctx, upstream, r)
}
