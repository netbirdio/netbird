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

	resolver.ProbeAvailability(context.TODO())

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
	var receivedUDPSize uint16
	udpHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if opt := r.IsEdns0(); opt != nil {
			receivedUDPSize = opt.UDPSize()
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
	assert.Equal(t, expectedMax, receivedUDPSize,
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
