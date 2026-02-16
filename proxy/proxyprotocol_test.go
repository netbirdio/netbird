package proxy

import (
	"net"
	"net/netip"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWrapProxyProtocol_OverridesRemoteAddr(t *testing.T) {
	srv := &Server{
		Logger:         log.StandardLogger(),
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		ProxyProtocol:  true,
	}

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer raw.Close()

	ln := srv.wrapProxyProtocol(raw)

	realClientIP := "203.0.113.50"
	realClientPort := uint16(54321)

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	// Connect and send a PROXY v2 header.
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	header := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr:        &net.TCPAddr{IP: net.ParseIP(realClientIP), Port: int(realClientPort)},
		DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443},
	}
	_, err = header.WriteTo(conn)
	require.NoError(t, err)

	select {
	case accepted := <-accepted:
		defer accepted.Close()
		host, _, err := net.SplitHostPort(accepted.RemoteAddr().String())
		require.NoError(t, err)
		assert.Equal(t, realClientIP, host, "RemoteAddr should reflect the PROXY header source IP")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for connection")
	}
}

func TestProxyProtocolPolicy_TrustedRequires(t *testing.T) {
	srv := &Server{
		Logger:         log.StandardLogger(),
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}

	opts := proxyproto.ConnPolicyOptions{
		Upstream: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234},
	}
	policy, err := srv.proxyProtocolPolicy(opts)
	require.NoError(t, err)
	assert.Equal(t, proxyproto.REQUIRE, policy, "trusted source should require PROXY header")
}

func TestProxyProtocolPolicy_UntrustedIgnores(t *testing.T) {
	srv := &Server{
		Logger:         log.StandardLogger(),
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}

	opts := proxyproto.ConnPolicyOptions{
		Upstream: &net.TCPAddr{IP: net.ParseIP("203.0.113.50"), Port: 1234},
	}
	policy, err := srv.proxyProtocolPolicy(opts)
	require.NoError(t, err)
	assert.Equal(t, proxyproto.IGNORE, policy, "untrusted source should have PROXY header ignored")
}

func TestProxyProtocolPolicy_InvalidIPRejects(t *testing.T) {
	srv := &Server{
		Logger:         log.StandardLogger(),
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}

	opts := proxyproto.ConnPolicyOptions{
		Upstream: &net.UnixAddr{Name: "/tmp/test.sock", Net: "unix"},
	}
	policy, err := srv.proxyProtocolPolicy(opts)
	require.NoError(t, err)
	assert.Equal(t, proxyproto.REJECT, policy, "unparsable address should be rejected")
}
