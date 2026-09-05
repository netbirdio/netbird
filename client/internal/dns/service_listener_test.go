package dns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

func TestServiceViaListener_TCPAndUDP(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.1"),
		})
		if err := w.WriteMsg(m); err != nil {
			t.Logf("write msg: %v", err)
		}
	})

	// Create a service using a custom address to avoid needing root
	svc := newServiceViaListener(nil, nil, nil)
	svc.dnsMux.Handle(".", handler)

	// Bind both transports up front to avoid TOCTOU races.
	udpAddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(customIP, 0))
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Skip("cannot bind to 127.0.0.153, skipping")
	}
	port := uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)

	tcpAddr := net.TCPAddrFromAddrPort(netip.AddrPortFrom(customIP, port))
	tcpLn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		udpConn.Close()
		t.Skip("cannot bind TCP on same port, skipping")
	}

	addr := fmt.Sprintf("%s:%d", customIP, port)
	svc.server.PacketConn = udpConn
	svc.tcpServer.Listener = tcpLn
	svc.listenIP = customIP
	svc.listenPort = port

	go func() {
		if err := svc.server.ActivateAndServe(); err != nil {
			t.Logf("udp server: %v", err)
		}
	}()
	go func() {
		if err := svc.tcpServer.ActivateAndServe(); err != nil {
			t.Logf("tcp server: %v", err)
		}
	}()
	svc.listenerIsRunning = true

	defer func() {
		require.NoError(t, svc.Stop())
	}()

	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)

	// Test UDP query
	udpClient := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	udpResp, _, err := udpClient.Exchange(q, addr)
	require.NoError(t, err, "UDP query should succeed")
	require.NotNil(t, udpResp)
	require.NotEmpty(t, udpResp.Answer)
	assert.Contains(t, udpResp.Answer[0].String(), "192.0.2.1", "UDP response should contain expected IP")

	// Test TCP query
	tcpClient := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
	tcpResp, _, err := tcpClient.Exchange(q, addr)
	require.NoError(t, err, "TCP query should succeed")
	require.NotNil(t, tcpResp)
	require.NotEmpty(t, tcpResp.Answer)
	assert.Contains(t, tcpResp.Answer[0].String(), "192.0.2.1", "TCP response should contain expected IP")
}

type dnatCall struct {
	rule  dnatRule
	added bool
}

// fakeFirewall records DNAT calls and fails the ones named in addErrs/removeErrs.
type fakeFirewall struct {
	calls      []dnatCall
	addErrs    map[firewall.Protocol]error
	removeErrs map[firewall.Protocol]error
}

func (f *fakeFirewall) AddOutputDNAT(ip netip.Addr, protocol firewall.Protocol, _, translatedPort uint16) error {
	if err := f.addErrs[protocol]; err != nil {
		return err
	}
	f.calls = append(f.calls, dnatCall{rule: dnatRule{protocol: protocol, ip: ip, port: translatedPort}, added: true})
	return nil
}

func (f *fakeFirewall) RemoveOutputDNAT(ip netip.Addr, protocol firewall.Protocol, _, translatedPort uint16) error {
	if err := f.removeErrs[protocol]; err != nil {
		return err
	}
	f.calls = append(f.calls, dnatCall{rule: dnatRule{protocol: protocol, ip: ip, port: translatedPort}})
	return nil
}

func newDNATTestService(fw Firewall) *serviceViaListener {
	return &serviceViaListener{
		listenIP:   netip.MustParseAddr("100.64.0.1"),
		listenPort: customPort,
		firewall:   fw,
	}
}

func TestSetupDNAT_BothProtocols(t *testing.T) {
	svc := newDNATTestService(&fakeFirewall{})

	svc.setupDNAT()

	assert.Len(t, svc.dnatRules, len(dnatProtocols))
	assert.Equal(t, DefaultPort, svc.RuntimePort(), "port 53 is advertised once both redirects are installed")
}

func TestSetupDNAT_RollsBackPartialRedirect(t *testing.T) {
	fw := &fakeFirewall{addErrs: map[firewall.Protocol]error{firewall.ProtocolTCP: errors.New("nftables busy")}}
	svc := newDNATTestService(fw)

	svc.setupDNAT()

	assert.Empty(t, svc.dnatRules, "the UDP redirect installed before the failure must be rolled back")
	assert.Equal(t, int(svc.listenPort), svc.RuntimePort(), "an incomplete redirect must not advertise port 53")
	udp := dnatRule{protocol: firewall.ProtocolUDP, ip: svc.listenIP, port: svc.listenPort}
	assert.Contains(t, fw.calls, dnatCall{rule: udp}, "UDP removal should have been attempted")
}

// A rollback that fails must keep the rule recorded, so port 53 is not left
// redirected to a resolver that no longer listens.
func TestStop_RetriesFailedDNATRemoval(t *testing.T) {
	fw := &fakeFirewall{
		addErrs:    map[firewall.Protocol]error{firewall.ProtocolTCP: errors.New("nftables busy")},
		removeErrs: map[firewall.Protocol]error{firewall.ProtocolUDP: errors.New("nftables busy")},
	}
	svc := newDNATTestService(fw)

	svc.setupDNAT()
	udp := dnatRule{protocol: firewall.ProtocolUDP, ip: svc.listenIP, port: svc.listenPort}
	require.Equal(t, []dnatRule{udp}, svc.dnatRules, "a failed rollback keeps the rule for a later retry")

	require.Error(t, svc.Stop(), "the failing removal should be reported")
	require.Equal(t, []dnatRule{udp}, svc.dnatRules)

	delete(fw.removeErrs, firewall.ProtocolUDP)
	require.NoError(t, svc.Stop(), "a later stop retries the removal")
	assert.Empty(t, svc.dnatRules)
}

// A rule left behind by a failed removal must be removed with the address and
// port it was installed with, even when the listener has since moved to another
// port, and it must not count towards the redirect the new listener advertises.
func TestSetupDNAT_ClearsStaleRuleAfterPortChange(t *testing.T) {
	fw := &fakeFirewall{removeErrs: map[firewall.Protocol]error{firewall.ProtocolUDP: errors.New("nftables busy")}}
	svc := newDNATTestService(fw)
	stalePort := svc.listenPort

	svc.setupDNAT()
	require.Error(t, svc.Stop())
	staleUDP := dnatRule{protocol: firewall.ProtocolUDP, ip: svc.listenIP, port: stalePort}
	require.Equal(t, []dnatRule{staleUDP}, svc.dnatRules)

	delete(fw.removeErrs, firewall.ProtocolUDP)
	svc.listenPort = stalePort + 1
	fw.calls = nil

	svc.setupDNAT()

	assert.Contains(t, fw.calls, dnatCall{rule: staleUDP}, "the stale rule must be removed with its original port")
	assert.Len(t, svc.dnatRules, len(dnatProtocols))
	assert.Equal(t, DefaultPort, svc.RuntimePort(), "the new listener is fully redirected")
	for _, rule := range svc.dnatRules {
		assert.Equal(t, svc.listenPort, rule.port, "only rules for the current listener remain")
	}
}
