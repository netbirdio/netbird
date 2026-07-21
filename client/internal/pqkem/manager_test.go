package pqkem

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManager_FullExchange(t *testing.T) {
	// deterministic roles: "bbbb" > "aaaa" -> B is initiator
	a := NewManager("aaaa")
	b := NewManager("bbbb")
	require.True(t, b.IsInitiator("aaaa"))
	require.False(t, a.IsInitiator("bbbb"))

	// B (initiator) -> A
	offer, err := b.StartExchange("aaaa")
	require.NoError(t, err)

	// A (responder) derives PSK but holds it pending
	answer, err := a.HandleOffer("bbbb", offer)
	require.NoError(t, err)

	// B derives PSK on the answer, commits now, produces confirm
	pskB, confirm, err := b.HandleAnswer("aaaa", answer)
	require.NoError(t, err)

	// A commits only on the confirm
	pskA, err := a.HandleConfirm("bbbb", confirm)
	require.NoError(t, err)

	require.Equal(t, pskB, pskA, "both sides converge on the same PSK")
	require.NotEqual(t, PSK{}, pskA)
}

func TestManager_StaleAnswerDropped(t *testing.T) {
	b := NewManager("bbbb")

	_, err := b.StartExchange("aaaa")
	require.NoError(t, err)

	// craft an answer with a wrong exchangeID
	stale := &AnswerMsg{ExchangeID: ExchangeID{0xFF}, KEMAnswer: make([]byte, AnswerSize)}
	_, _, err = b.HandleAnswer("aaaa", stale)
	require.Error(t, err)
}

func TestManager_RestartResyncsViaNewExchange(t *testing.T) {
	// A restarts (fresh manager) mid-flight; a new exchange from scratch converges.
	a := NewManager("aaaa")
	b := NewManager("bbbb")

	off1, err := b.StartExchange("aaaa")
	require.NoError(t, err)

	// B "restarts": new manager, old in-flight state gone
	b = NewManager("bbbb")
	off2, err := b.StartExchange("aaaa")
	require.NoError(t, err)
	require.NotEqual(t, off1.ExchangeID, off2.ExchangeID)

	ans, err := a.HandleOffer("bbbb", off2)
	require.NoError(t, err)
	pskB, conf, err := b.HandleAnswer("aaaa", ans)
	require.NoError(t, err)
	pskA, err := a.HandleConfirm("bbbb", conf)
	require.NoError(t, err)
	require.Equal(t, pskB, pskA)
}

func TestManager_UnknownPeerErrors(t *testing.T) {
	a := NewManager("aaaa")
	_, err := a.HandleConfirm("zzzz", &ConfirmMsg{})
	require.Error(t, err)
}
