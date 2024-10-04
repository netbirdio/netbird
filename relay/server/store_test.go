package server

import (
	"context"
	"net"
	"testing"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/netbirdio/netbird/relay/metrics"
)

type mockConn struct {
}

func (m mockConn) Read(b []byte) (n int, err error) {
	//TODO implement me
	panic("implement me")
}

func (m mockConn) Write(b []byte) (n int, err error) {
	//TODO implement me
	panic("implement me")
}

func (m mockConn) Close() error {
	return nil
}

func (m mockConn) LocalAddr() net.Addr {
	//TODO implement me
	panic("implement me")
}

func (m mockConn) RemoteAddr() net.Addr {
	//TODO implement me
	panic("implement me")
}

func (m mockConn) SetDeadline(t time.Time) error {
	//TODO implement me
	panic("implement me")
}

func (m mockConn) SetReadDeadline(t time.Time) error {
	//TODO implement me
	panic("implement me")
}

func (m mockConn) SetWriteDeadline(t time.Time) error {
	//TODO implement me
	panic("implement me")
}

func TestStore_DeletePeer(t *testing.T) {
	s := NewStore()

	m, _ := metrics.NewMetrics(context.Background(), otel.Meter(""))

	p := NewPeer(m, []byte("peer_one"), nil, nil)
	s.AddPeer(p)
	s.DeletePeer(p)
	if _, ok := s.Peer(p.String()); ok {
		t.Errorf("peer was not deleted")
	}
}

func TestStore_DeleteDeprecatedPeer(t *testing.T) {
	s := NewStore()

	m, _ := metrics.NewMetrics(context.Background(), otel.Meter(""))

	conn := &mockConn{}
	p1 := NewPeer(m, []byte("peer_id"), conn, nil)
	p2 := NewPeer(m, []byte("peer_id"), conn, nil)

	s.AddPeer(p1)
	s.AddPeer(p2)
	s.DeletePeer(p1)

	if _, ok := s.Peer(p2.String()); !ok {
		t.Errorf("second peer was deleted")
	}
}
