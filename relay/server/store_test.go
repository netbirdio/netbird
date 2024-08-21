package server

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"

	"github.com/netbirdio/netbird/relay/metrics"
)

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

	p1 := NewPeer(m, []byte("peer_id"), nil, nil)
	p2 := NewPeer(m, []byte("peer_id"), nil, nil)

	s.AddPeer(p1)
	s.AddPeer(p2)
	s.DeletePeer(p1)

	if _, ok := s.Peer(p2.String()); !ok {
		t.Errorf("second peer was deleted")
	}
}
