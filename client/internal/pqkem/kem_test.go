package pqkem

import (
	"testing"
	"time"

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

	answer, pskB, err := Respond(init.Offer(), Binding{LocalWgPub: wgB, RemoteWgPub: wgA})
	require.NoError(t, err)
	require.Len(t, answer, AnswerSize)

	pskA, err := init.Finish(answer, Binding{LocalWgPub: wgA, RemoteWgPub: wgB})
	require.NoError(t, err)

	require.Equal(t, pskB, pskA, "both sides must derive the same PSK")
	require.NotEqual(t, PSK{}, pskA, "PSK must not be zero")
}

func TestExchange_PSKBoundToPeerIdentities(t *testing.T) {
	init, err := NewInitiator()
	require.NoError(t, err)

	// responder computes with the honest pair...
	_, pskHonest, err := Respond(init.Offer(), Binding{LocalWgPub: wgB, RemoteWgPub: wgA})
	require.NoError(t, err)

	// ...a second responder run with a different peer identity yields a different PSK,
	// even though the KEM material would otherwise combine identically.
	wgC := []byte("peer-C-wireguard-pubkey-32bytes!")
	_, pskWrong, err := Respond(init.Offer(), Binding{LocalWgPub: wgC, RemoteWgPub: wgA})
	require.NoError(t, err)

	require.NotEqual(t, pskHonest, pskWrong, "PSK must be bound to the peer pair")
}

func TestExchange_RejectsMalformedMessages(t *testing.T) {
	init, err := NewInitiator()
	require.NoError(t, err)

	_, _, err = Respond(init.Offer()[:10], Binding{})
	require.Error(t, err)

	_, err = init.Finish([]byte("too short"), Binding{})
	require.Error(t, err)
}

// TestExchange_ReportSizesAndTiming is a spike measurement, not a pass/fail gate.
// Run with: go test -run TestExchange_ReportSizesAndTiming -v ./client/internal/pqkem/
func TestExchange_ReportSizesAndTiming(t *testing.T) {
	const iters = 200

	var tInit, tResp, tFinish time.Duration
	for i := 0; i < iters; i++ {
		s0 := time.Now()
		init, err := NewInitiator()
		require.NoError(t, err)
		tInit += time.Since(s0)

		s1 := time.Now()
		answer, _, err := Respond(init.Offer(), Binding{LocalWgPub: wgB, RemoteWgPub: wgA})
		require.NoError(t, err)
		tResp += time.Since(s1)

		s2 := time.Now()
		_, err = init.Finish(answer, Binding{LocalWgPub: wgA, RemoteWgPub: wgB})
		require.NoError(t, err)
		tFinish += time.Since(s2)
	}

	t.Logf("wire sizes:   offer=%d B   answer=%d B   (Rosenpass static pubkey ~524160 B)", OfferSize, AnswerSize)
	t.Logf("total on-wire per handshake: %d B  (~%.0fx smaller than RP static key)", OfferSize+AnswerSize, 524160.0/float64(OfferSize+AnswerSize))
	t.Logf("avg NewInitiator (keygen): %s", tInit/iters)
	t.Logf("avg Respond (encaps+dh):   %s", tResp/iters)
	t.Logf("avg Finish (decaps+dh):    %s", tFinish/iters)
	t.Logf("avg full handshake CPU:    %s", (tInit+tResp+tFinish)/iters)
}
