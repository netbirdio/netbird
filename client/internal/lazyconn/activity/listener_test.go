package activity

import (
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/lazyconn"
)

func TestNewListener(t *testing.T) {
	peer := &MocPeer{
		PeerID: "examplePublicKey1",
	}

	cfg := lazyconn.PeerConfig{
		PublicKey:  peer.PeerID,
		PeerConnID: peer.ConnID(),
		Log:        log.WithField("peer", "examplePublicKey1"),
	}

	l, err := NewListener(MocWGIface{}, cfg)
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	chanClosed := make(chan struct{})
	go func() {
		defer close(chanClosed)
		l.ReadPackets()
	}()

	time.Sleep(1 * time.Second)
	l.Close()

	select {
	case <-chanClosed:
	case <-time.After(time.Second):
	}
}
