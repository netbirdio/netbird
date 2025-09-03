package wgproxy

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/netbirdio/netbird/util"
)

func TestMain(m *testing.M) {
	_ = util.InitLog("trace", util.LogConsole)
	code := m.Run()
	os.Exit(code)
}

type proxyInstance struct {
	name         string
	proxy        Proxy
	wgPort       int
	endpointAddr *net.UDPAddr
	closeFn      func() error
}

type mocConn struct {
	closeChan chan struct{}
	closed    bool
}

func newMockConn() *mocConn {
	return &mocConn{
		closeChan: make(chan struct{}),
	}
}

func (m *mocConn) Read(b []byte) (n int, err error) {
	<-m.closeChan
	return 0, io.EOF
}

func (m *mocConn) Write(b []byte) (n int, err error) {
	<-m.closeChan
	return 0, io.EOF
}

func (m *mocConn) Close() error {
	if m.closed == true {
		return nil
	}

	m.closed = true
	close(m.closeChan)
	return nil
}

func (m *mocConn) LocalAddr() net.Addr {
	panic("implement me")
}

func (m *mocConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{
		IP: net.ParseIP("172.16.254.1"),
	}
}

func (m *mocConn) SetDeadline(t time.Time) error {
	panic("implement me")
}

func (m *mocConn) SetReadDeadline(t time.Time) error {
	panic("implement me")
}

func (m *mocConn) SetWriteDeadline(t time.Time) error {
	panic("implement me")
}

func TestProxyCloseByRemoteConn(t *testing.T) {
	ctx := context.Background()

	tests, err := seedProxyForProxyCloseByRemoteConn()
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	relayedConn, _ := net.Dial("udp", "127.0.0.1:1234")
	defer func() {
		_ = relayedConn.Close()
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			relayedConn := newMockConn()
			err := tt.proxy.AddTurnConn(ctx, nil, relayedConn)
			if err != nil {
				t.Errorf("error: %v", err)
			}

			_ = relayedConn.Close()
			if err := tt.proxy.CloseConn(); err != nil {
				t.Errorf("error: %v", err)
			}
		})
	}
}

// TestProxyRedirect todo extend the proxies with Bind proxy
func TestProxyRedirect(t *testing.T) {
	tests, err := seedProxies()
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			redirectTraffic(t, tt.proxy, tt.wgPort, tt.endpointAddr)
			if err := tt.closeFn(); err != nil {
				t.Errorf("error: %v", err)
			}
		})
	}
}

func redirectTraffic(t *testing.T, proxy Proxy, wgPort int, endPointAddr *net.UDPAddr) {
	t.Helper()

	msgHelloFromRelay := []byte("hello from relay")
	msgRedirected := [][]byte{
		[]byte("hello 1. to p2p"),
		[]byte("hello 2. to p2p"),
		[]byte("hello 3. to p2p"),
	}

	dummyWgListener, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: wgPort})
	if err != nil {
		t.Fatalf("failed to listen on udp port: %s", err)
	}

	relayedServer, _ := net.ListenUDP("udp",
		&net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 1234,
		},
	)

	relayedConn, _ := net.Dial("udp", "127.0.0.1:1234")

	defer func() {
		_ = dummyWgListener.Close()
		_ = relayedConn.Close()
		_ = relayedServer.Close()
	}()

	if err := proxy.AddTurnConn(context.Background(), endPointAddr, relayedConn); err != nil {
		t.Errorf("error: %v", err)
	}
	defer func() {
		if err := proxy.CloseConn(); err != nil {
			t.Errorf("error: %v", err)
		}
	}()

	proxy.Work()

	if _, err := relayedServer.WriteTo(msgHelloFromRelay, relayedConn.LocalAddr()); err != nil {
		t.Errorf("error relayedServer.Write(msgHelloFromRelay): %v", err)
	}

	n, err := dummyWgListener.Read(make([]byte, 1024))
	if err != nil {
		t.Errorf("error: %v", err)
	}

	if n != len(msgHelloFromRelay) {
		t.Errorf("expected %d bytes, got %d", len(msgHelloFromRelay), n)
	}

	p2pEndpointAddr := &net.UDPAddr{
		IP:   net.IPv4(192, 168, 0, 56),
		Port: 1234,
	}
	proxy.RedirectAs(p2pEndpointAddr)

	for _, msg := range msgRedirected {
		if _, err := relayedServer.WriteTo(msg, relayedConn.LocalAddr()); err != nil {
			t.Errorf("error: %v", err)
		}
	}

	for i := 0; i < len(msgRedirected); i++ {
		buf := make([]byte, 1024)
		n, rAddr, err := dummyWgListener.ReadFrom(buf)
		if err != nil {
			t.Errorf("error: %v", err)
		}

		if rAddr.String() != p2pEndpointAddr.String() {
			t.Errorf("expected %s, got %s", p2pEndpointAddr.String(), rAddr.String())
		}
		if string(buf[:n]) != string(msgRedirected[i]) {
			t.Errorf("expected %s, got %s", string(msgRedirected[i]), string(buf[:n]))
		}
	}
}
