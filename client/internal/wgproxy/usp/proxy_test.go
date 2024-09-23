package usp

import (
	"context"
	"github.com/netbirdio/netbird/util"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	_ = util.InitLog("trace", "console")
	code := m.Run()
	os.Exit(code)
}

type mocConn struct {
	closeChane chan struct{}
	closed     bool
}

func newMockConn() *mocConn {
	return &mocConn{
		closeChane: make(chan struct{}),
	}
}

func (m *mocConn) Read(b []byte) (n int, err error) {
	<-m.closeChane
	return 0, io.EOF
}

func (m *mocConn) Write(b []byte) (n int, err error) {
	<-m.closeChane
	return 0, io.EOF
}

func (m *mocConn) Close() error {
	if m.closed == true {
		return nil
	}

	m.closed = true
	close(m.closeChane)
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

func TestNewWGUserSpaceProxy(t *testing.T) {
	ctx := context.Background()
	wgPort := 51820
	proxy := NewWGUserSpaceProxy(wgPort)
	rconn := newMockConn()
	_, err := proxy.AddTurnConn(ctx, rconn)
	if err != nil {
		t.Errorf("error: %v", err)
	}

	_ = rconn.Close()
}
