package peer

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
)

func newRelayOnlyTestHandshaker(t *testing.T) *Handshaker {
	t.Helper()
	// No relay server URLs: RelayInstanceAddress fails and the offer simply
	// carries no relay address, which is all these tests need.
	mgr := relayClient.NewManager(t.Context(), nil, "local", iface.DefaultMTU)
	relay := NewWorkerRelay(t.Context(), log.WithField("test", t.Name()), false, ConnConfig{}, nil, mgr)
	return NewHandshaker(log.WithField("test", t.Name()), ConnConfig{}, nil, nil, relay, nil)
}

// A peer that offers no ICE credentials still has to identify its connection,
// otherwise the remote cannot tell a restarted peer from a repeated offer and
// keeps the relayed connection and overlay session of the previous instance.
func TestHandshakerRelayOnlyOfferCarriesSessionID(t *testing.T) {
	h := newRelayOnlyTestHandshaker(t)

	first := h.buildOfferAnswer()
	second := h.buildOfferAnswer()

	require.False(t, first.hasICECredentials(), "precondition: the offer is relay-only")
	require.NotNil(t, first.SessionID, "relay-only offer must carry a session ID")
	require.NotNil(t, second.SessionID, "relay-only offer must carry a session ID")
	assert.Equal(t, *first.SessionID, *second.SessionID, "offers of one connection must share a session ID")

	restarted := newRelayOnlyTestHandshaker(t).buildOfferAnswer()
	require.NotNil(t, restarted.SessionID, "relay-only offer must carry a session ID")
	assert.NotEqual(t, *first.SessionID, *restarted.SessionID, "a new connection must use a new session ID")
}

func TestWorkerRelayDetectsRemoteRestart(t *testing.T) {
	sid := func(s string) *ICESessionID {
		id := ICESessionID(s)
		return &id
	}
	iceCreds := IceCredentials{UFrag: "ufrag", Pwd: "pwd"}

	tests := []struct {
		name   string
		offers []OfferAnswer
		want   []bool
	}{
		{
			name:   "first offer is not a restart",
			offers: []OfferAnswer{{SessionID: sid("aaaaaaaaaa")}},
			want:   []bool{false},
		},
		{
			name:   "repeated session is not a restart",
			offers: []OfferAnswer{{SessionID: sid("aaaaaaaaaa")}, {SessionID: sid("aaaaaaaaaa")}},
			want:   []bool{false, false},
		},
		{
			name:   "new session is a restart",
			offers: []OfferAnswer{{SessionID: sid("aaaaaaaaaa")}, {SessionID: sid("bbbbbbbbbb")}},
			want:   []bool{false, true},
		},
		{
			// ICE session IDs rotate with the ICE agent, not with the peer, so they
			// say nothing about a restart and must not reset the tracked session.
			name: "ICE offers are ignored",
			offers: []OfferAnswer{
				{SessionID: sid("aaaaaaaaaa")},
				{SessionID: sid("cccccccccc"), IceCredentials: iceCreds},
				{SessionID: sid("aaaaaaaaaa")},
			},
			want: []bool{false, false, false},
		},
		{
			// Peers that predate session IDs in relay-only offers send none.
			name:   "offers without a session are ignored",
			offers: []OfferAnswer{{SessionID: sid("aaaaaaaaaa")}, {}, {SessionID: sid("aaaaaaaaaa")}},
			want:   []bool{false, false, false},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := &WorkerRelay{}
			for i := range tc.offers {
				assert.Equal(t, tc.want[i], w.remoteRestarted(&tc.offers[i]), "offer %d", i)
			}
		})
	}
}
