package alignedhb

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

func TestSignedPhaseStore(t *testing.T) {
	alice := messages.HashID("alice")
	bob := messages.HashID("bob")
	t.Cleanup(func() { lastSigned.Store(nil) })

	_, _, ok := LoadSignedPhase(alice)
	assert.False(t, ok, "nothing stored yet")

	sig := []byte{1, 2, 3}
	StoreSignedPhase(alice, time.Minute, SignedPhase{Phase: 5 * time.Second, Day: 7, Signature: sig})
	sig[0] = 9

	period, sp, ok := LoadSignedPhase(alice)
	require.True(t, ok, "stored phase of the same peer")
	assert.Equal(t, time.Minute, period, "period")
	assert.Equal(t, SignedPhase{Phase: 5 * time.Second, Day: 7, Signature: []byte{1, 2, 3}}, sp,
		"the store must not alias the caller's signature")
	sp.Signature[1] = 9
	_, again, _ := LoadSignedPhase(alice)
	assert.Equal(t, []byte{1, 2, 3}, again.Signature, "a loaded signature must not alias the store")

	_, _, ok = LoadSignedPhase(bob)
	assert.False(t, ok, "the phase of another peer must not be returned")

	ClearSignedPhase(bob)
	_, _, ok = LoadSignedPhase(alice)
	assert.True(t, ok, "clearing another peer must keep the stored phase")

	ClearSignedPhase(alice)
	_, _, ok = LoadSignedPhase(alice)
	assert.False(t, ok, "cleared")
}

func TestSignedPhaseSeqAndNotify(t *testing.T) {
	alice := messages.HashID("alice-seq")
	t.Cleanup(func() { lastSigned.Store(nil) })
	sp := SignedPhase{Phase: time.Second, Day: 1, Signature: []byte{1}}

	changed := SignedPhaseChanged()
	StoreSignedPhase(alice, time.Minute, sp)
	select {
	case <-changed:
	default:
		t.Fatal("a new phase must wake the waiters")
	}
	first, ok := LoadStoredPhase(alice)
	require.True(t, ok)

	changed = SignedPhaseChanged()
	StoreSignedPhase(alice, time.Minute, SignedPhase{Phase: time.Second, Day: 1, Signature: []byte{1}})
	select {
	case <-changed:
		t.Fatal("the same phase again must not wake the waiters")
	default:
	}
	same, _ := LoadStoredPhase(alice)
	assert.Equal(t, first.Seq, same.Seq, "the same phase keeps its sequence number")

	sp.Day = 2
	StoreSignedPhase(alice, time.Minute, sp)
	select {
	case <-changed:
	default:
		t.Fatal("the phase of a new day must wake the waiters")
	}
	next, _ := LoadStoredPhase(alice)
	assert.Greater(t, next.Seq, first.Seq, "a new phase gets a higher sequence number")
	assert.Equal(t, time.Minute, next.Period, "period")
	assert.Equal(t, int64(2), next.Signed.Day, "day")
}

// An aligned Management answer wakes the waiters even when the phase is the
// one already stored, and each answer closes only the channel taken before it.
func TestSignedAnswerAnnounced(t *testing.T) {
	first := SignedAnswerAnnounced()
	select {
	case <-first:
		t.Fatal("no answer announced yet")
	default:
	}

	AnnounceSignedAnswer()
	select {
	case <-first:
	default:
		t.Fatal("an answer must wake the waiters")
	}

	second := SignedAnswerAnnounced()
	select {
	case <-second:
		t.Fatal("a channel taken after the answer must wait for the next one")
	default:
	}
	AnnounceSignedAnswer()
	select {
	case <-second:
	default:
		t.Fatal("the next answer must wake the new waiters")
	}
}
