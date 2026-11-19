//go:build devcert

package quic

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbRelay "github.com/netbirdio/netbird/shared/relay"
	quictls "github.com/netbirdio/netbird/shared/relay/tls"
)

// udpBlackhole forwards UDP between one client and a server until drop is set,
// then it discards every packet in both directions: a network that went dead
// without telling either side.
type udpBlackhole struct {
	front  *net.UDPConn
	back   *net.UDPConn
	drop   atomic.Bool
	client atomic.Pointer[net.UDPAddr]
}

func TestWriteTimesOutWhenNetworkGoesDead(t *testing.T) {
	proxy := startUDPBlackhole(t, startHoldingQUICServer(t))

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := (Dialer{}).Dial(dialCtx, "rel://"+proxy.front.LocalAddr().String(), "")
	cancel()
	require.NoError(t, err, "dial through the proxy")
	t.Cleanup(func() {
		_ = conn.Close()
	})

	quicConn, ok := conn.(*Conn)
	require.True(t, ok, "the dialer must return a quic connection")
	quicConn.writeTimeout = 200 * time.Millisecond

	payload := make([]byte, 1000)
	_, err = conn.Write(payload)
	require.NoError(t, err, "write on a working network")

	proxy.drop.Store(true)

	// QUIC keeps accepting datagrams for a while after the network is gone, so
	// the writer has to keep going until the send queue stops draining.
	writeErr := make(chan error, 1)
	go func() {
		for {
			if _, err := conn.Write(payload); err != nil {
				writeErr <- err
				return
			}
		}
	}()

	select {
	case err := <-writeErr:
		assert.ErrorIs(t, err, os.ErrDeadlineExceeded, "a blocked write must end with the write timeout")
	case <-time.After(20 * time.Second):
		t.Fatal("write did not return although the network went dead")
	}

	_, err = conn.Write(payload)
	assert.Error(t, err, "a write after the timeout must fail")
	assert.NotErrorIs(t, err, os.ErrDeadlineExceeded, "the connection must be closed once a write has timed out")
}

// startHoldingQUICServer listens with the relay server's QUIC configuration,
// accepts one connection and keeps it open without reading.
func startHoldingQUICServer(t *testing.T) net.Addr {
	t.Helper()

	tlsConf, err := quictls.ServerQUICTLSConfig(nil)
	require.NoError(t, err, "server TLS config")
	ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: nbRelay.QUICInitialPacketSize,
	})
	require.NoError(t, err, "listen")

	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(func() {
		stop()
		_ = ln.Close()
	})
	go func() {
		session, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		<-ctx.Done()
		_ = session.CloseWithError(0, "test done")
	}()
	return ln.Addr()
}

func startUDPBlackhole(t *testing.T, target net.Addr) *udpBlackhole {
	t.Helper()

	targetAddr, err := net.ResolveUDPAddr("udp", target.String())
	require.NoError(t, err, "resolve the proxy target")
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err, "listen for the proxy")
	back, err := net.DialUDP("udp", nil, targetAddr)
	require.NoError(t, err, "dial the proxy target")

	p := &udpBlackhole{front: front, back: back}
	t.Cleanup(func() {
		_ = front.Close()
		_ = back.Close()
	})

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			p.client.Store(addr)
			if !p.drop.Load() {
				_, _ = back.Write(buf[:n])
			}
		}
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			if addr := p.client.Load(); addr != nil && !p.drop.Load() {
				_, _ = front.WriteToUDP(buf[:n], addr)
			}
		}
	}()
	return p
}
