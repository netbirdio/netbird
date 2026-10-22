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

// bootstrapPQ is a fakePQ whose controller decisions are set by the test.
type bootstrapPQ struct {
	fakePQ
	bootstrap bool
	inFlight  bool
	offer     []byte
}

func (b bootstrapPQ) OfferPayload(string) ([]byte, uint16) { return b.offer, 0 }

func (b bootstrapPQ) ShouldSendBootstrapOffer(string) bool { return b.bootstrap }
func (b bootstrapPQ) SignalOfferInFlight(string) bool      { return b.inFlight }

// newControllerHandshaker builds a handshaker for the controller side of a peer pair and
// records the body of every signalling message it sends.
func newControllerHandshaker(t *testing.T, pq PQHandshaker) (*Handshaker, func() []*sProto.Body) {
	t.Helper()
	var mu sync.Mutex
	var sent []*sProto.Body
	client := &signal.MockClient{
		ReadyFunc: func() bool { return true },
		SendFunc: func(msg *sProto.Message) error {
			mu.Lock()
			defer mu.Unlock()
			sent = append(sent, msg.GetBody())
			return nil
		},
	}
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	config := ConnConfig{Key: "aaaa", LocalKey: "bbbb", PQ: pq} // LocalKey > Key: controller
	relay := &WorkerRelay{relayManager: &relayClient.Manager{}}
	h := NewHandshaker(log.WithField("test", t.Name()), config, NewSignaler(client, key), nil, relay, nil)
	return h, func() []*sProto.Body {
		mu.Lock()
		defer mu.Unlock()
		return append([]*sProto.Body(nil), sent...)
	}
}

func bodyTypes(bodies []*sProto.Body) []sProto.Body_Type {
	types := make([]sProto.Body_Type, 0, len(bodies))
	for _, b := range bodies {
		types = append(types, b.GetType())
	}
	return types
}

// TestHandshaker_ControllerReoffersOnResponderOffer drives the responder-originated
// reconnect through the handshaker: when the KEM manager asks for a fresh bootstrap, the
// controller replies to the responder's KEM-less offer with its own offer and sends no
// answer, so the reconnect re-derives one PSK on both sides.
func TestHandshaker_ControllerReoffersOnResponderOffer(t *testing.T) {
	h, sent := newControllerHandshaker(t, bootstrapPQ{bootstrap: true})

	h.handleRemoteOffer(OfferAnswer{})

	assert.Equal(t, []sProto.Body_Type{sProto.Body_OFFER}, bodyTypes(sent()),
		"the controller must reply with its own offer, not an answer")
}

// TestHandshaker_ControllerResendsOfferInGlare covers an offer glare: the controller's KEM
// offer and the responder's KEM-less offer cross. The controller must not answer: a
// KEM-less answer could reach the responder before the KEM offer and let it bring WireGuard
// up with no PSK. It sends its in-flight offer again instead, in case the first send failed.
func TestHandshaker_ControllerResendsOfferInGlare(t *testing.T) {
	inFlightOffer := []byte("in-flight KEM offer")
	h, sent := newControllerHandshaker(t, bootstrapPQ{inFlight: true, offer: inFlightOffer})
	notified := false
	h.AddICEListener(func(*OfferAnswer) { notified = true }) // called synchronously

	h.handleRemoteOffer(OfferAnswer{IceCredentials: IceCredentials{UFrag: "ufrag", Pwd: "pwd"}})

	bodies := sent()
	require.Len(t, bodies, 1, "in a glare the controller must send exactly one message")
	assert.Equal(t, sProto.Body_OFFER, bodies[0].GetType(), "in a glare the controller must resend its offer, not answer")
	assert.Equal(t, inFlightOffer, bodies[0].GetMlkemPayload(), "the resend must carry the in-flight KEM offer")
	assert.False(t, notified, "in a glare the controller must not bring the connection up from the responder's offer")
}

// TestHandshaker_ControllerAnswersNonCapablePeer keeps the normal answer when there is no
// KEM to run with the peer: its offer is then the only copy of its connection details.
func TestHandshaker_ControllerAnswersNonCapablePeer(t *testing.T) {
	h, sent := newControllerHandshaker(t, bootstrapPQ{})

	h.handleRemoteOffer(OfferAnswer{})

	assert.Equal(t, []sProto.Body_Type{sProto.Body_ANSWER}, bodyTypes(sent()),
		"without a KEM to run the controller must answer normally")
}
