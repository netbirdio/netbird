package peer

import (
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	signal "github.com/netbirdio/netbird/shared/signal/client"
	sProto "github.com/netbirdio/netbird/shared/signal/proto"
)

func newTestHandshaker(t *testing.T) *Handshaker {
	t.Helper()

	localKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate local key: %v", err)
	}
	remoteKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate remote key: %v", err)
	}

	signaler := NewSignaler(&signal.MockClient{
		ReadyFunc: func() bool { return true },
		SendFunc:  func(*sProto.Message) error { return nil },
	}, localKey)

	cfg := ConnConfig{
		Key:      remoteKey.PublicKey().String(),
		LocalKey: localKey.PublicKey().String(),
	}

	return NewHandshaker(log.WithField("test", t.Name()), cfg, signaler, nil, nil, nil)
}

// TestHandshakerHoldsSignalArrivingBeforeListen covers the case where a peer is
// activated by an incoming signal: the remote's offer/answer arrives in the same
// step that opens the connection, before the Listen loop starts reading. The
// message must be held rather than dropped, or the connection cannot proceed until
// the remote re-sends. This is the path taken when an eager peer connects to a
// lazily-managed one.
//
// The answer path is used because its Listen branch dispatches to the same
// listeners as the offer path without also sending an answer, so it exercises the
// buffered-channel behavior (which covers both channels) without needing a relay.
func TestHandshakerHoldsSignalArrivingBeforeListen(t *testing.T) {
	h := newTestHandshaker(t)

	processed := make(chan struct{}, 4)
	h.AddRelayListener(func(*OfferAnswer) { processed <- struct{}{} })

	// Delivered before Listen is reading, exactly as when the peer is woken by the
	// remote's signal and the message is delivered right after Open.
	h.OnRemoteAnswer(OfferAnswer{
		WgListenPort:   51820,
		IceCredentials: IceCredentials{UFrag: "ufrag", Pwd: "pwd"},
	})

	go h.Listen(t.Context())

	select {
	case <-processed:
	case <-time.After(2 * time.Second):
		t.Fatal("signal that arrived before Listen was ready was dropped")
	}
}
