package pqkem

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	wgA = []byte("peer-A-wireguard-pubkey-32bytes!")
	wgB = []byte("peer-B-wireguard-pubkey-32bytes!")
)

func TestExchange_DerivesMatchingPSK(t *testing.T) {
	init, err := NewInitiator()
	require.NoError(t, err)

	require.Len(t, init.Offer(), OfferSize)

	answer, pskB, err := Respond(init.Offer(), Binding{LocalID: wgB, RemoteID: wgA})
	require.NoError(t, err)
	require.Len(t, answer, AnswerSize)

	pskA, err := init.Finish(answer, Binding{LocalID: wgA, RemoteID: wgB})
	require.NoError(t, err)

	require.Equal(t, pskB, pskA, "both sides must derive the same PSK")
	require.NotEqual(t, PSK{}, pskA, "PSK must not be zero")
}

func TestExchange_PSKBoundToPeerIdentities(t *testing.T) {
	init, err := NewInitiator()
	require.NoError(t, err)

	answer, _, err := Respond(init.Offer(), Binding{LocalID: wgB, RemoteID: wgA})
	require.NoError(t, err)

	// Finish twice over the SAME KEM material (same offer/answer/secrets), changing only
	// the peer identity binding: the differing PSK is attributable to the binding alone.
	pskHonest, err := init.Finish(answer, Binding{LocalID: wgA, RemoteID: wgB})
	require.NoError(t, err)

	wgC := []byte("peer-C-wireguard-pubkey-32bytes!")
	pskWrong, err := init.Finish(answer, Binding{LocalID: wgA, RemoteID: wgC})
	require.NoError(t, err)

	require.NotEqual(t, pskHonest, pskWrong, "PSK must be bound to the peer pair")
}

func TestExchange_RejectsEmptyBinding(t *testing.T) {
	init, err := NewInitiator()
	require.NoError(t, err)
	answer, _, err := Respond(init.Offer(), Binding{LocalID: wgB, RemoteID: wgA})
	require.NoError(t, err)

	// A PSK not bound to both identities could be transplanted to another peer pair.
	_, err = init.Finish(answer, Binding{})
	require.Error(t, err, "empty binding must be rejected")
	_, err = init.Finish(answer, Binding{LocalID: wgA})
	require.Error(t, err, "missing RemoteID must be rejected")
	_, _, err = Respond(init.Offer(), Binding{RemoteID: wgA})
	require.Error(t, err, "missing LocalID must be rejected")
}

func TestExchange_RejectsMalformedMessages(t *testing.T) {
	init, err := NewInitiator()
	require.NoError(t, err)

	_, _, err = Respond(init.Offer()[:10], Binding{})
	require.Error(t, err)

	_, err = init.Finish([]byte("too short"), Binding{})
	require.Error(t, err)
}

// BenchmarkExchange measures a full hybrid exchange (keygen, encapsulation, decapsulation)
// and reports its on-wire size.
// Run with: go test -run '^$' -bench BenchmarkExchange ./client/internal/pqkem/
func BenchmarkExchange(b *testing.B) {
	for i := 0; i < b.N; i++ {
		init, err := NewInitiator()
		require.NoError(b, err)
		answer, _, err := Respond(init.Offer(), Binding{LocalID: wgB, RemoteID: wgA})
		require.NoError(b, err)
		_, err = init.Finish(answer, Binding{LocalID: wgA, RemoteID: wgB})
		require.NoError(b, err)
	}
	b.ReportMetric(float64(OfferSize+AnswerSize), "wire-B/exchange")
}
