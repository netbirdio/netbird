package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
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
			resolver.addRace(servers)
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

type mockUpstreamResponse struct {
	msg   *dns.Msg
	err   error
	delay time.Duration
}

type mockUpstreamResolverPerServer struct {
	responses map[string]mockUpstreamResponse
	rtt       time.Duration
}

func (c mockUpstreamResolverPerServer) exchange(ctx context.Context, upstream string, _ *dns.Msg) (*dns.Msg, time.Duration, error) {
	r, ok := c.responses[upstream]
	if !ok {
		return nil, c.rtt, fmt.Errorf("no mock response for %s", upstream)
	}
	if r.delay > 0 {
		select {
		case <-time.After(r.delay):
		case <-ctx.Done():
			return nil, c.rtt, ctx.Err()
		}
	}
	return r.msg, c.rtt, r.err
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
				upstreamTimeout: UpstreamTimeout,
			}
			resolver.addRace([]netip.AddrPort{upstream1, upstream2})

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
		upstreamTimeout: UpstreamTimeout,
	}
	resolver.addRace([]netip.AddrPort{upstream})

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

// TestUpstreamResolver_RaceAcrossGroups covers two nameserver groups
// configured for the same domain, with one broken group. The merge+race
// path should answer as fast as the working group and not pay the timeout
// of the broken one on every query.
func TestUpstreamResolver_RaceAcrossGroups(t *testing.T) {
	broken := netip.MustParseAddrPort("192.0.2.1:53")
	working := netip.MustParseAddrPort("192.0.2.2:53")
	successAnswer := "192.0.2.100"
	timeoutErr := &net.OpError{Op: "read", Err: fmt.Errorf("i/o timeout")}

	mockClient := &mockUpstreamResolverPerServer{
		responses: map[string]mockUpstreamResponse{
			// Force the broken upstream to only unblock via timeout /
			// cancellation so the assertion below can't pass if races
			// were run serially.
			broken.String():  {err: timeoutErr, delay: 500 * time.Millisecond},
			working.String(): {msg: buildMockResponse(dns.RcodeSuccess, successAnswer)},
		},
		rtt: time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver := &upstreamResolverBase{
		ctx:             ctx,
		upstreamClient:  mockClient,
		upstreamTimeout: 250 * time.Millisecond,
	}
	resolver.addRace([]netip.AddrPort{broken})
	resolver.addRace([]netip.AddrPort{working})

	var responseMSG *dns.Msg
	responseWriter := &test.MockResponseWriter{
		WriteMsgFunc: func(m *dns.Msg) error {
			responseMSG = m
			return nil
		},
	}

	inputMSG := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	start := time.Now()
	resolver.ServeDNS(responseWriter, inputMSG)
	elapsed := time.Since(start)

	require.NotNil(t, responseMSG, "should write a response")
	assert.Equal(t, dns.RcodeSuccess, responseMSG.Rcode)
	require.NotEmpty(t, responseMSG.Answer)
	assert.Contains(t, responseMSG.Answer[0].String(), successAnswer)
	// Working group answers in a single RTT; the broken group's
	// timeout (100ms) must not block the response.
	assert.Less(t, elapsed, 100*time.Millisecond, "race must not wait for broken group's timeout")
}

// TestUpstreamResolver_AllGroupsFail checks that when every group fails the
// resolver returns SERVFAIL rather than leaking a partial response.
func TestUpstreamResolver_AllGroupsFail(t *testing.T) {
	a := netip.MustParseAddrPort("192.0.2.1:53")
	b := netip.MustParseAddrPort("192.0.2.2:53")

	mockClient := &mockUpstreamResolverPerServer{
		responses: map[string]mockUpstreamResponse{
			a.String(): {msg: buildMockResponse(dns.RcodeServerFailure, "")},
			b.String(): {msg: buildMockResponse(dns.RcodeServerFailure, "")},
		},
		rtt: time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver := &upstreamResolverBase{
		ctx:             ctx,
		upstreamClient:  mockClient,
		upstreamTimeout: UpstreamTimeout,
	}
	resolver.addRace([]netip.AddrPort{a})
	resolver.addRace([]netip.AddrPort{b})

	var responseMSG *dns.Msg
	responseWriter := &test.MockResponseWriter{
		WriteMsgFunc: func(m *dns.Msg) error {
			responseMSG = m
			return nil
		},
	}

	resolver.ServeDNS(responseWriter, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	require.NotNil(t, responseMSG)
	assert.Equal(t, dns.RcodeServerFailure, responseMSG.Rcode)
}

// TestUpstreamResolver_HealthTracking verifies that query-path results are
// recorded into per-upstream health, which is what projects back to
// NSGroupState for status reporting.
func TestUpstreamResolver_HealthTracking(t *testing.T) {
	ok := netip.MustParseAddrPort("192.0.2.10:53")
	bad := netip.MustParseAddrPort("192.0.2.11:53")

	mockClient := &mockUpstreamResolverPerServer{
		responses: map[string]mockUpstreamResponse{
			ok.String():  {msg: buildMockResponse(dns.RcodeSuccess, "192.0.2.100")},
			bad.String(): {msg: buildMockResponse(dns.RcodeServerFailure, "")},
		},
		rtt: time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver := &upstreamResolverBase{
		ctx:             ctx,
		upstreamClient:  mockClient,
		upstreamTimeout: UpstreamTimeout,
	}
	resolver.addRace([]netip.AddrPort{ok, bad})

	responseWriter := &test.MockResponseWriter{WriteMsgFunc: func(m *dns.Msg) error { return nil }}
	resolver.ServeDNS(responseWriter, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))

	health := resolver.UpstreamHealth()
	require.Contains(t, health, ok)
	assert.False(t, health[ok].LastOk.IsZero(), "ok upstream should have LastOk set")
	assert.Empty(t, health[ok].LastErr)

	// bad upstream was never tried because ok answered first; its health
	// should remain unset.
	assert.NotContains(t, health, bad, "sibling upstream should not be queried when primary answers")
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

func TestDNSProtocolContext(t *testing.T) {
	t.Run("roundtrip udp", func(t *testing.T) {
		ctx := contextWithDNSProtocol(context.Background(), protoUDP)
		assert.Equal(t, protoUDP, dnsProtocolFromContext(ctx))
	})

	t.Run("roundtrip tcp", func(t *testing.T) {
		ctx := contextWithDNSProtocol(context.Background(), protoTCP)
		assert.Equal(t, protoTCP, dnsProtocolFromContext(ctx))
	})

	t.Run("missing returns empty", func(t *testing.T) {
		assert.Equal(t, "", dnsProtocolFromContext(context.Background()))
	})
}

func TestExchangeWithFallback_TCPContext(t *testing.T) {
	// Start a local DNS server that responds on TCP only
	tcpHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.1"),
		})
		if err := w.WriteMsg(m); err != nil {
			t.Logf("write msg: %v", err)
		}
	})

	tcpServer := &dns.Server{
		Addr:    "127.0.0.1:0",
		Net:     "tcp",
		Handler: tcpHandler,
	}

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tcpServer.Listener = tcpLn

	go func() {
		if err := tcpServer.ActivateAndServe(); err != nil {
			t.Logf("tcp server: %v", err)
		}
	}()
	defer func() {
		_ = tcpServer.Shutdown()
	}()

	upstream := tcpLn.Addr().String()

	// With TCP context, should connect directly via TCP without trying UDP
	ctx := contextWithDNSProtocol(context.Background(), protoTCP)
	client := &dns.Client{Timeout: 2 * time.Second}
	r := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)

	rm, _, err := ExchangeWithFallback(ctx, client, r, upstream)
	require.NoError(t, err)
	require.NotNil(t, rm)
	require.NotEmpty(t, rm.Answer)
	assert.Contains(t, rm.Answer[0].String(), "10.0.0.1")
}

func TestExchangeWithFallback_UDPFallbackToTCP(t *testing.T) {
	// UDP handler returns a truncated response to trigger TCP retry.
	udpHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		if err := w.WriteMsg(m); err != nil {
			t.Logf("write msg: %v", err)
		}
	})

	// TCP handler returns the full answer.
	tcpHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.3"),
		})
		if err := w.WriteMsg(m); err != nil {
			t.Logf("write msg: %v", err)
		}
	})

	udpPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := udpPC.LocalAddr().String()

	udpServer := &dns.Server{
		PacketConn: udpPC,
		Net:        "udp",
		Handler:    udpHandler,
	}

	tcpLn, err := net.Listen("tcp", addr)
	require.NoError(t, err)

	tcpServer := &dns.Server{
		Listener: tcpLn,
		Net:      "tcp",
		Handler:  tcpHandler,
	}

	go func() {
		if err := udpServer.ActivateAndServe(); err != nil {
			t.Logf("udp server: %v", err)
		}
	}()
	go func() {
		if err := tcpServer.ActivateAndServe(); err != nil {
			t.Logf("tcp server: %v", err)
		}
	}()
	defer func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	}()

	ctx := context.Background()
	client := &dns.Client{Timeout: 2 * time.Second}
	r := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)

	rm, _, err := ExchangeWithFallback(ctx, client, r, addr)
	require.NoError(t, err, "should fall back to TCP after truncated UDP response")
	require.NotNil(t, rm)
	require.NotEmpty(t, rm.Answer, "TCP response should contain the full answer")
	assert.Contains(t, rm.Answer[0].String(), "10.0.0.3")
	assert.False(t, rm.Truncated, "TCP response should not be truncated")
}

func TestExchangeWithFallback_TCPContextSkipsUDP(t *testing.T) {
	// Start only a TCP server (no UDP). With TCP context it should succeed.
	tcpHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.2"),
		})
		if err := w.WriteMsg(m); err != nil {
			t.Logf("write msg: %v", err)
		}
	})

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	tcpServer := &dns.Server{
		Listener: tcpLn,
		Net:      "tcp",
		Handler:  tcpHandler,
	}

	go func() {
		if err := tcpServer.ActivateAndServe(); err != nil {
			t.Logf("tcp server: %v", err)
		}
	}()
	defer func() {
		_ = tcpServer.Shutdown()
	}()

	upstream := tcpLn.Addr().String()

	// TCP context: should skip UDP entirely and go directly to TCP
	ctx := contextWithDNSProtocol(context.Background(), protoTCP)
	client := &dns.Client{Timeout: 2 * time.Second}
	r := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)

	rm, _, err := ExchangeWithFallback(ctx, client, r, upstream)
	require.NoError(t, err)
	require.NotNil(t, rm)
	require.NotEmpty(t, rm.Answer)
	assert.Contains(t, rm.Answer[0].String(), "10.0.0.2")

	// Without TCP context, trying to reach a TCP-only server via UDP should fail
	ctx2 := context.Background()
	client2 := &dns.Client{Timeout: 500 * time.Millisecond}
	_, _, err = ExchangeWithFallback(ctx2, client2, r, upstream)
	assert.Error(t, err, "should fail when no UDP server and no TCP context")
}

func TestExchangeWithFallback_EDNS0Capped(t *testing.T) {
	// Verify that a client EDNS0 larger than our MTU-derived limit gets
	// capped in the outgoing request so the upstream doesn't send a
	// response larger than our read buffer.
	var receivedUDPSize atomic.Uint32
	udpHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if opt := r.IsEdns0(); opt != nil {
			receivedUDPSize.Store(uint32(opt.UDPSize()))
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.0.0.1"),
		})
		if err := w.WriteMsg(m); err != nil {
			t.Logf("write msg: %v", err)
		}
	})

	udpPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := udpPC.LocalAddr().String()

	udpServer := &dns.Server{PacketConn: udpPC, Net: "udp", Handler: udpHandler}
	go func() { _ = udpServer.ActivateAndServe() }()
	t.Cleanup(func() { _ = udpServer.Shutdown() })

	ctx := context.Background()
	client := &dns.Client{Timeout: 2 * time.Second}
	r := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	r.SetEdns0(4096, false)

	rm, _, err := ExchangeWithFallback(ctx, client, r, addr)
	require.NoError(t, err)
	require.NotNil(t, rm)

	expectedMax := uint16(currentMTU - ipUDPHeaderSize)
	assert.Equal(t, expectedMax, uint16(receivedUDPSize.Load()),
		"upstream should see capped EDNS0, not the client's 4096")
}

func TestExchangeWithFallback_TCPTruncatesToClientSize(t *testing.T) {
	// When the client advertises a large EDNS0 (4096) and the upstream
	// truncates, the TCP response should NOT be truncated since the full
	// answer fits within the client's original buffer.
	udpHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		if err := w.WriteMsg(m); err != nil {
			t.Logf("write msg: %v", err)
		}
	})

	tcpHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		// Add enough records to exceed MTU but fit within 4096
		for i := range 20 {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{fmt.Sprintf("record-%d-padding-data-to-make-it-longer", i)},
			})
		}
		if err := w.WriteMsg(m); err != nil {
			t.Logf("write msg: %v", err)
		}
	})

	udpPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := udpPC.LocalAddr().String()

	udpServer := &dns.Server{PacketConn: udpPC, Net: "udp", Handler: udpHandler}
	tcpLn, err := net.Listen("tcp", addr)
	require.NoError(t, err)
	tcpServer := &dns.Server{Listener: tcpLn, Net: "tcp", Handler: tcpHandler}

	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})

	ctx := context.Background()
	client := &dns.Client{Timeout: 2 * time.Second}

	// Client with large buffer: should get all records without truncation
	r := new(dns.Msg).SetQuestion("example.com.", dns.TypeTXT)
	r.SetEdns0(4096, false)

	rm, _, err := ExchangeWithFallback(ctx, client, r, addr)
	require.NoError(t, err)
	require.NotNil(t, rm)
	assert.Len(t, rm.Answer, 20, "large EDNS0 client should get all records")
	assert.False(t, rm.Truncated, "response should not be truncated for large buffer client")

	// Client with small buffer: should get truncated response
	r2 := new(dns.Msg).SetQuestion("example.com.", dns.TypeTXT)
	r2.SetEdns0(512, false)

	rm2, _, err := ExchangeWithFallback(ctx, &dns.Client{Timeout: 2 * time.Second}, r2, addr)
	require.NoError(t, err)
	require.NotNil(t, rm2)
	assert.Less(t, len(rm2.Answer), 20, "small EDNS0 client should get fewer records")
	assert.True(t, rm2.Truncated, "response should be truncated for small buffer client")
}

func msgWithEDE(rcode int, codes ...uint16) *dns.Msg {
	m := new(dns.Msg)
	m.Response = true
	m.Rcode = rcode
	if len(codes) == 0 {
		return m
	}
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(dns.MinMsgSize)
	for _, c := range codes {
		opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: c})
	}
	m.Extra = append(m.Extra, opt)
	return m
}

func TestNonRetryableEDE(t *testing.T) {
	tests := []struct {
		name     string
		msg      *dns.Msg
		wantOK   bool
		wantCode uint16
	}{
		{name: "no edns0", msg: msgWithEDE(dns.RcodeServerFailure)},
		{
			name: "opt without ede",
			msg: func() *dns.Msg {
				m := msgWithEDE(dns.RcodeServerFailure)
				opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
				opt.Option = append(opt.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID})
				m.Extra = []dns.RR{opt}
				return m
			}(),
		},
		{name: "ede dnsbogus", msg: msgWithEDE(dns.RcodeServerFailure, dns.ExtendedErrorCodeDNSBogus), wantOK: true, wantCode: dns.ExtendedErrorCodeDNSBogus},
		{name: "ede signature expired", msg: msgWithEDE(dns.RcodeServerFailure, dns.ExtendedErrorCodeSignatureExpired), wantOK: true, wantCode: dns.ExtendedErrorCodeSignatureExpired},
		{name: "ede blocked", msg: msgWithEDE(dns.RcodeServerFailure, dns.ExtendedErrorCodeBlocked), wantOK: true, wantCode: dns.ExtendedErrorCodeBlocked},
		{name: "ede prohibited", msg: msgWithEDE(dns.RcodeRefused, dns.ExtendedErrorCodeProhibited), wantOK: true, wantCode: dns.ExtendedErrorCodeProhibited},
		{name: "ede cached error retryable", msg: msgWithEDE(dns.RcodeServerFailure, dns.ExtendedErrorCodeCachedError)},
		{name: "ede network error retryable", msg: msgWithEDE(dns.RcodeServerFailure, dns.ExtendedErrorCodeNetworkError)},
		{name: "ede not ready retryable", msg: msgWithEDE(dns.RcodeServerFailure, dns.ExtendedErrorCodeNotReady)},
		{
			name:     "first non-retryable wins",
			msg:      msgWithEDE(dns.RcodeServerFailure, dns.ExtendedErrorCodeNetworkError, dns.ExtendedErrorCodeDNSBogus),
			wantOK:   true,
			wantCode: dns.ExtendedErrorCodeDNSBogus,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, ok := nonRetryableEDE(tc.msg)
			assert.Equal(t, tc.wantOK, ok, "ok should match")
			if tc.wantOK {
				assert.Equal(t, tc.wantCode, code, "code should match")
			}
		})
	}
}

func TestEDEName(t *testing.T) {
	assert.Equal(t, "DNSSEC Bogus", edeName(dns.ExtendedErrorCodeDNSBogus))
	assert.Equal(t, "Signature Expired", edeName(dns.ExtendedErrorCodeSignatureExpired))
	assert.Equal(t, "EDE 9999", edeName(9999), "unknown code falls back to numeric")
}

func TestStripOPT(t *testing.T) {
	rm := &dns.Msg{
		Extra: []dns.RR{
			&dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}},
			&dns.A{Hdr: dns.RR_Header{Name: "x.", Rrtype: dns.TypeA}, A: net.IPv4(1, 2, 3, 4)},
		},
	}
	stripOPT(rm)
	assert.Len(t, rm.Extra, 1, "OPT should be removed, A kept")
	_, isOPT := rm.Extra[0].(*dns.OPT)
	assert.False(t, isOPT, "remaining record must not be OPT")
}

func TestUpstreamResolver_NonRetryableEDEShortCircuits(t *testing.T) {
	upstream1 := netip.MustParseAddrPort("192.0.2.1:53")
	upstream2 := netip.MustParseAddrPort("192.0.2.2:53")

	servfailWithEDE := msgWithEDE(dns.RcodeServerFailure, dns.ExtendedErrorCodeDNSBogus)
	successResp := buildMockResponse(dns.RcodeSuccess, "192.0.2.100")

	var queried []string
	tracking := &trackingMockClient{
		inner: &mockUpstreamResolverPerServer{
			responses: map[string]mockUpstreamResponse{
				upstream1.String(): {msg: servfailWithEDE},
				upstream2.String(): {msg: successResp},
			},
			rtt: time.Millisecond,
		},
		queriedUpstreams: &queried,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver := &upstreamResolverBase{
		ctx:             ctx,
		upstreamClient:  tracking,
		upstreamServers: []upstreamRace{{upstream1, upstream2}},
		upstreamTimeout: UpstreamTimeout,
	}

	var written *dns.Msg
	w := &test.MockResponseWriter{
		WriteMsgFunc: func(m *dns.Msg) error {
			written = m
			return nil
		},
	}

	// Client query without EDNS0 must not see an OPT in the response.
	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	resolver.ServeDNS(w, q)

	require.NotNil(t, written, "response must be written")
	assert.Equal(t, dns.RcodeServerFailure, written.Rcode, "SERVFAIL must propagate")
	assert.Len(t, queried, 1, "only first upstream should be queried")
	assert.Equal(t, upstream1.String(), queried[0])
	for _, rr := range written.Extra {
		_, isOPT := rr.(*dns.OPT)
		assert.False(t, isOPT, "synthetic OPT must not leak to a non-EDNS0 client")
	}
}
