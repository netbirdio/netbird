package phasesig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

const testSecret = "relay-auth-secret"

func peerID(n int) messages.PeerID {
	return messages.HashID("peer-public-key-" + string(rune('a'+n)))
}

func TestDay(t *testing.T) {
	assert.Equal(t, int64(0), Day(time.Unix(0, 0)), "epoch is day 0")
	assert.Equal(t, int64(0), Day(time.Unix(secondsPerDay-1, 0)), "last second of day 0")
	assert.Equal(t, int64(1), Day(time.Unix(secondsPerDay, 0)), "first second of day 1")
	assert.Equal(t, int64(-1), Day(time.Unix(-1, 0)), "second before epoch is day -1")
}

func TestNewSigner_EmptySecret(t *testing.T) {
	_, err := NewSigner("")
	assert.ErrorIs(t, err, ErrNoSecret)
}

func TestNewVerifier_NoUsableSecret(t *testing.T) {
	_, err := NewVerifier()
	assert.ErrorIs(t, err, ErrNoSecret)
	_, err = NewVerifier("", "")
	assert.ErrorIs(t, err, ErrNoSecret)
}

func TestPhase_SameOnTwoInstances(t *testing.T) {
	// Two Management instances, or one before and after a restart, build their
	// signer from the same secret and must hand out the same signed phase.
	a, err := NewSigner(testSecret)
	require.NoError(t, err)
	b, err := NewSigner(testSecret)
	require.NoError(t, err)

	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	later := now.Add(11 * time.Hour)
	spA, err := a.SignedPhase(peerID(0), time.Minute, now)
	require.NoError(t, err)
	spB, err := b.SignedPhase(peerID(0), time.Minute, later)
	require.NoError(t, err)

	assert.Equal(t, spA, spB, "same key, same day must give the same signed phase")
}

func TestPhase_ChangesWithDayAndPeer(t *testing.T) {
	s, err := NewSigner(testSecret)
	require.NoError(t, err)

	const day = 20405
	changedDays := 0
	for d := int64(1); d <= 10; d++ {
		if s.Phase(peerID(0), time.Minute, day) != s.Phase(peerID(0), time.Minute, day+d) {
			changedDays++
		}
	}
	// One equal pair in 60000 is possible, ten in a row is not.
	assert.Greater(t, changedDays, 8, "phase must change on the next days")

	assert.NotEqual(t, s.Phase(peerID(0), time.Minute, day), s.Phase(peerID(1), time.Minute, day),
		"two peers should get different phases")
}

func TestPhase_DependsOnSecret(t *testing.T) {
	a, err := NewSigner(testSecret)
	require.NoError(t, err)
	b, err := NewSigner("other-secret")
	require.NoError(t, err)

	differ := 0
	for i := 0; i < 10; i++ {
		if a.Phase(peerID(i), time.Minute, 1) != b.Phase(peerID(i), time.Minute, 1) {
			differ++
		}
	}
	assert.Greater(t, differ, 8, "phase must depend on the secret")
}

func TestPhase_InsidePeriodAndSpread(t *testing.T) {
	s, err := NewSigner(testSecret)
	require.NoError(t, err)

	const peers = 2000
	period := time.Minute
	buckets := make([]int, 10)
	for i := 0; i < peers; i++ {
		p := s.Phase(messages.HashID(string(rune(i))+"-key"), period, 20405)
		require.True(t, p >= 0 && p < period, "phase %s outside period", p)
		require.Zero(t, p%time.Millisecond, "phase must be whole ms")
		buckets[int(p*10/period)]++
	}
	// Expect 200 per 6 s bucket. A fair hash stays well within half and double.
	for i, n := range buckets {
		assert.True(t, n > peers/20 && n < peers/5, "bucket %d has %d peers, phases not spread", i, n)
	}
}

func TestPhase_ZeroPeriod(t *testing.T) {
	s, err := NewSigner(testSecret)
	require.NoError(t, err)
	assert.Zero(t, s.Phase(peerID(0), 0, 1), "no phase without a period")
}

func TestVerify(t *testing.T) {
	s, err := NewSigner(testSecret)
	require.NoError(t, err)
	v, err := NewVerifier(testSecret)
	require.NoError(t, err)

	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	sp, err := s.SignedPhase(peerID(0), time.Minute, now)
	require.NoError(t, err)
	require.Len(t, sp.Signature, SignatureSize)

	assert.NoError(t, v.Verify(peerID(0), time.Minute, sp, now), "own signature must verify")
	assert.NoError(t, v.Verify(peerID(0), time.Minute, sp, now.Add(24*time.Hour)),
		"signature from yesterday must verify, for a client during a Management outage")
	assert.NoError(t, v.Verify(peerID(0), time.Minute, sp, now.Add(-24*time.Hour)),
		"signature from tomorrow must verify, for small clock differences at midnight")

	assert.ErrorIs(t, v.Verify(peerID(0), time.Minute, sp, now.Add(48*time.Hour)), ErrDayOutOfRange)
	assert.ErrorIs(t, v.Verify(peerID(1), time.Minute, sp, now), ErrBadSignature, "other peer key")
	assert.ErrorIs(t, v.Verify(peerID(0), 2*time.Minute, sp, now), ErrBadSignature, "other period")

	moved := sp
	moved.Phase = (sp.Phase + time.Second) % time.Minute
	assert.ErrorIs(t, v.Verify(peerID(0), time.Minute, moved, now), ErrBadSignature, "phase picked by the client")

	otherDay := sp
	otherDay.Day = sp.Day + 1
	assert.ErrorIs(t, v.Verify(peerID(0), time.Minute, otherDay, now), ErrBadSignature, "day changed by the client")

	flipped := sp
	flipped.Signature = append([]byte(nil), sp.Signature...)
	flipped.Signature[0] ^= 1
	assert.ErrorIs(t, v.Verify(peerID(0), time.Minute, flipped, now), ErrBadSignature, "changed signature")

	short := sp
	short.Signature = sp.Signature[:16]
	assert.ErrorIs(t, v.Verify(peerID(0), time.Minute, short, now), ErrBadSignature, "truncated signature")

	outside := sp
	outside.Phase = time.Minute
	assert.ErrorIs(t, v.Verify(peerID(0), time.Minute, outside, now), ErrInvalidPhase, "phase outside period")
}

func TestVerify_WrongSecret(t *testing.T) {
	s, err := NewSigner(testSecret)
	require.NoError(t, err)
	v, err := NewVerifier("other-secret")
	require.NoError(t, err)

	now := time.Now()
	sp, err := s.SignedPhase(peerID(0), time.Minute, now)
	require.NoError(t, err)
	assert.ErrorIs(t, v.Verify(peerID(0), time.Minute, sp, now), ErrBadSignature)
}

func TestVerify_Rotation(t *testing.T) {
	// During a rotation Signal and relay accept the old and the new secret, so
	// phases signed before and after Management switches both stay valid.
	oldSigner, err := NewSigner("old-secret")
	require.NoError(t, err)
	newSigner, err := NewSigner("new-secret")
	require.NoError(t, err)
	v, err := NewVerifier("new-secret", "", "old-secret", "new-secret")
	require.NoError(t, err)
	assert.Len(t, v.keys, 2, "empty and repeated secrets must be skipped")

	now := time.Now()
	spOld, err := oldSigner.SignedPhase(peerID(0), time.Minute, now)
	require.NoError(t, err)
	spNew, err := newSigner.SignedPhase(peerID(0), time.Minute, now)
	require.NoError(t, err)

	assert.NoError(t, v.Verify(peerID(0), time.Minute, spOld, now), "old secret")
	assert.NoError(t, v.Verify(peerID(0), time.Minute, spNew, now), "new secret")
}

func TestSignedPhase_InvalidPeriod(t *testing.T) {
	s, err := NewSigner(testSecret)
	require.NoError(t, err)
	_, err = s.SignedPhase(peerID(0), 1500*time.Millisecond, time.Now())
	assert.ErrorIs(t, err, ErrInvalidPhase, "period must be whole seconds")
	_, err = s.SignedPhase(peerID(0), 0, time.Now())
	assert.ErrorIs(t, err, ErrInvalidPhase, "zero period")
}
