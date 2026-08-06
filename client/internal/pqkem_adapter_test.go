package internal

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/pqkem"
)

type pqNoopHandler struct{}

func (pqNoopHandler) OnNewPSKReady(pqkem.RemoteID, pqkem.PSK, bool) error { return nil }
func (pqNoopHandler) OnRekeyFailed(pqkem.RemoteID) error                  { return nil }

// TestPQAdapter_CapabilityRoleAware locks the role-aware capability signal: the KEM
// payload only flows initiator-offer -> responder-answer, so an empty message in the
// other direction comes from a perfectly capable peer and must NOT flag it. Only the
// message that should carry material (the answer we receive as initiator) marks a peer
// non-capable when empty.
func TestPQAdapter_CapabilityRoleAware(t *testing.T) {
	// localID "zzzz" > "aaaa" => this manager is the KEM initiator for peer "aaaa".
	mgr := pqkem.NewManager("zzzz", pqNoopHandler{}, nil)
	defer mgr.Stop()
	h := pqHandshaker{mgr: mgr}

	// An empty OFFER from our peer is normal here: as the initiator's responder it puts
	// its material in the answer, not the offer. It must not disable our offering.
	h.AnswerPayload("aaaa", nil)
	payload, _ := h.OfferPayload("aaaa")
	require.NotNil(t, payload, "an empty offer from a responder-role peer must not mark it non-capable")

	// An empty ANSWER to our offer means the peer does not run the KEM -> stop offering.
	h.OnAnswer("aaaa", nil)
	payload2, _ := h.OfferPayload("aaaa")
	require.Nil(t, payload2, "an empty answer to our offer marks the peer non-capable, so we stop offering")
}
