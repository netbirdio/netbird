package peer

import (
	"fmt"
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

func TestWorkerRelayTracksRemoteSession(t *testing.T) {
	sid := func(s string) *ICESessionID {
		id := ICESessionID(s)
		return &id
	}
	iceCreds := IceCredentials{UFrag: "ufrag", Pwd: "pwd"}

	tests := []struct {
		name   string
		offers []OfferAnswer
		want   []remoteSessionState
	}{
		{
			name:   "first offer is not a restart",
			offers: []OfferAnswer{{SessionID: sid("aaaaaaaaaa")}},
			want:   []remoteSessionState{remoteSessionCurrent},
		},
		{
			name:   "repeated session is not a restart",
			offers: []OfferAnswer{{SessionID: sid("aaaaaaaaaa")}, {SessionID: sid("aaaaaaaaaa")}},
			want:   []remoteSessionState{remoteSessionCurrent, remoteSessionCurrent},
		},
		{
			name:   "new session is a restart",
			offers: []OfferAnswer{{SessionID: sid("aaaaaaaaaa")}, {SessionID: sid("bbbbbbbbbb")}},
			want:   []remoteSessionState{remoteSessionCurrent, remoteSessionRestarted},
		},
		{
			// ICE session IDs rotate with the ICE agent, not with the peer, so ICE
			// offers alone say nothing about a restart.
			name: "ICE offers before any relay-only offer are not a restart",
			offers: []OfferAnswer{
				{SessionID: sid("cccccccccc"), IceCredentials: iceCreds},
				{SessionID: sid("dddddddddd"), IceCredentials: iceCreds},
				{SessionID: sid("aaaaaaaaaa")},
			},
			want: []remoteSessionState{remoteSessionCurrent, remoteSessionCurrent, remoteSessionCurrent},
		},
		{
			// A peer with ICE starts every connection with ICE offers and switches to
			// relay-only offers once it learns this side has no ICE. An ICE offer after
			// relay-only ones therefore comes from a new connection, and the relay-only
			// offers it sends later must not be taken for one more restart.
			name: "ICE offer after relay-only offers is a restart",
			offers: []OfferAnswer{
				{SessionID: sid("aaaaaaaaaa")},
				{SessionID: sid("cccccccccc"), IceCredentials: iceCreds},
				{SessionID: sid("aaaaaaaaaa")},
				{SessionID: sid("bbbbbbbbbb")},
				{SessionID: sid("bbbbbbbbbb")},
			},
			want: []remoteSessionState{remoteSessionCurrent, remoteSessionRestarted, remoteSessionSuperseded, remoteSessionCurrent, remoteSessionCurrent},
		},
		{
			// An offer of the previous session delivered late must not be taken
			// for yet another restart and tear down the new session's connection.
			name: "late offer of a superseded session is ignored",
			offers: []OfferAnswer{
				{SessionID: sid("aaaaaaaaaa")},
				{SessionID: sid("bbbbbbbbbb")},
				{SessionID: sid("aaaaaaaaaa")},
				{SessionID: sid("bbbbbbbbbb")},
			},
			want: []remoteSessionState{remoteSessionCurrent, remoteSessionRestarted, remoteSessionSuperseded, remoteSessionCurrent},
		},
		{
			// Peers that predate session IDs in relay-only offers send none.
			name:   "offers without a session are ignored",
			offers: []OfferAnswer{{SessionID: sid("aaaaaaaaaa")}, {}, {SessionID: sid("aaaaaaaaaa")}},
			want:   []remoteSessionState{remoteSessionCurrent, remoteSessionCurrent, remoteSessionCurrent},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := &WorkerRelay{}
			for i := range tc.offers {
				assert.Equal(t, tc.want[i], w.trackRemoteSession(&tc.offers[i]), "offer %d", i)
			}
		})
	}
}

// Only the most recent replaced sessions are remembered, so the history stays bounded.
func TestWorkerRelaySupersededSessionHistoryIsBounded(t *testing.T) {
	w := &WorkerRelay{}
	for i := 0; i <= maxSupersededSessionIDs+1; i++ {
		id := ICESessionID(fmt.Sprintf("session-%02d", i))
		w.trackRemoteSession(&OfferAnswer{SessionID: &id})
	}

	assert.Len(t, w.supersededSessionIDs, maxSupersededSessionIDs, "superseded history size")
	oldest := ICESessionID("session-00")
	assert.Equal(t, remoteSessionRestarted, w.trackRemoteSession(&OfferAnswer{SessionID: &oldest}), "a session older than the history is not recognized")
}
