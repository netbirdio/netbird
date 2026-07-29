package rosenpass

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeterministicSeedKey_SameForBothSides(t *testing.T) {
	// Peer A and peer B must derive the same PSK regardless of which side
	// computes it: the function orders inputs internally.
	a := strings.Repeat("a", 32)
	b := strings.Repeat("b", 32)

	keyAB, err := DeterministicSeedKey(a, b)
	require.NoError(t, err)
	keyBA, err := DeterministicSeedKey(b, a)
	require.NoError(t, err)
	require.Equal(t, keyAB.String(), keyBA.String(), "swapping arguments must yield identical key")
}

func TestDeterministicSeedKey_ChangesWithKeys(t *testing.T) {
	a := strings.Repeat("a", 32)
	b := strings.Repeat("b", 32)
	c := strings.Repeat("c", 32)

	keyAB, err := DeterministicSeedKey(a, b)
	require.NoError(t, err)
	keyAC, err := DeterministicSeedKey(a, c)
	require.NoError(t, err)
	require.NotEqual(t, keyAB.String(), keyAC.String(), "different peer pair must yield different key")
}

func TestDeterministicSeedKey_TooShortKey_ReturnsError(t *testing.T) {
	short := "short" // < 16 bytes
	long := strings.Repeat("x", 32)

	_, err := DeterministicSeedKey(short, long)
	require.Error(t, err)
	_, err = DeterministicSeedKey(long, short)
	require.Error(t, err)
}
