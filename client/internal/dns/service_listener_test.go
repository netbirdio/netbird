package dns

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
