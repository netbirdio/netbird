//go:build linux

package wgproxy

import (
	"context"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/netbirdio/netbird/client/iface/wgproxy/ebpf"
	udpProxy "github.com/netbirdio/netbird/client/iface/wgproxy/udp"
	"github.com/netbirdio/netbird/util"
)

func TestMain(m *testing.M) {
	_ = util.InitLog("trace", "console")
	code := m.Run()
	os.Exit(code)
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

	tests := []struct {
		name  string
		proxy Proxy
	}{
		{
			name:  "userspace proxy",
			proxy: udpProxy.NewWGUDPProxy(51830),
		},
	}

	if runtime.GOOS == "linux" && os.Getenv("GITHUB_ACTIONS") != "true" {
		ebpfProxy := ebpf.NewWGEBPFProxy(51831)
		if err := ebpfProxy.Listen(); err != nil {
			t.Fatalf("failed to initialize ebpf proxy: %s", err)
		}
		defer func() {
			if err := ebpfProxy.Free(); err != nil {
				t.Errorf("failed to free ebpf proxy: %s", err)
			}
		}()
		proxyWrapper := ebpf.NewProxyWrapper(ebpfProxy)

		tests = append(tests, struct {
			name  string
			proxy Proxy
		}{
			name:  "ebpf proxy",
			proxy: proxyWrapper,
		})
	}

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
