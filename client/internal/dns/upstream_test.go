package dns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
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
