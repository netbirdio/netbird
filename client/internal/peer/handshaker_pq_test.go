package peer

import (
	"sync"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	relayClient "github.com/netbirdio/netbird/shared/relay/client"
	signal "github.com/netbirdio/netbird/shared/signal/client"
	sProto "github.com/netbirdio/netbird/shared/signal/proto"
)

// bootstrapPQ is a fakePQ whose controller decision is set by the test.
type bootstrapPQ struct {
	fakePQ
	bootstrap bool
}

func (b bootstrapPQ) ShouldSendBootstrapOffer(string) bool { return b.bootstrap }

// newControllerHandshaker builds a handshaker for the controller side of a peer pair and
// records the type of every signalling message it sends.
func newControllerHandshaker(t *testing.T, pq PQHandshaker) (*Handshaker, func() []sProto.Body_Type) {
	t.Helper()
	var mu sync.Mutex
	var sent []sProto.Body_Type
	client := &signal.MockClient{
		ReadyFunc: func() bool { return true },
		SendFunc: func(msg *sProto.Message) error {
			mu.Lock()
			defer mu.Unlock()
			sent = append(sent, msg.GetBody().GetType())
			return nil
		},
	}
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	config := ConnConfig{Key: "aaaa", LocalKey: "bbbb", PQ: pq} // LocalKey > Key: controller
	relay := &WorkerRelay{relayManager: &relayClient.Manager{}}
	h := NewHandshaker(log.WithField("test", t.Name()), config, NewSignaler(client, key), nil, relay, nil)
	return h, func() []sProto.Body_Type {
		mu.Lock()
		defer mu.Unlock()
		return append([]sProto.Body_Type(nil), sent...)
	}
}

// TestHandshaker_ControllerReoffersOnResponderOffer drives the responder-originated
// reconnect through the handshaker: when the KEM manager asks for a fresh bootstrap, the
// controller replies to the responder's KEM-less offer with its own offer and sends no
// answer, so the reconnect re-derives one PSK on both sides.
func TestHandshaker_ControllerReoffersOnResponderOffer(t *testing.T) {
	h, sent := newControllerHandshaker(t, bootstrapPQ{bootstrap: true})

	h.handleRemoteOffer(OfferAnswer{})

	assert.Equal(t, []sProto.Body_Type{sProto.Body_OFFER}, sent(),
		"the controller must reply with its own offer, not an answer")
}

// TestHandshaker_ControllerAnswersWhileExchangeInFlight keeps the glare protection: with
// the controller's own exchange in flight, the responder's offer gets a normal answer.
func TestHandshaker_ControllerAnswersWhileExchangeInFlight(t *testing.T) {
	h, sent := newControllerHandshaker(t, bootstrapPQ{bootstrap: false})

	h.handleRemoteOffer(OfferAnswer{})

	assert.Equal(t, []sProto.Body_Type{sProto.Body_ANSWER}, sent(),
		"with an exchange in flight the controller must answer normally")
}
