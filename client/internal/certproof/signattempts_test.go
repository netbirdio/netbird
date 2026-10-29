package certproof

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errNeedsApprovalForTest = errors.New("key needs approval")

// TestSignAttempts_FallsThroughToTheNextIdentity: a certificate can sit in a keychain with
// more than one key, of which only some can sign. A failure moves on, and an identity that
// signs ends the search without reporting the earlier failure.
func TestSignAttempts_FallsThroughToTheNextIdentity(t *testing.T) {
	var attempts signAttempts

	signature, ok := attempts.try(func() ([]byte, error) { return nil, errNeedsApprovalForTest })
	assert.False(t, ok, "a failing identity does not end the search")
	assert.Nil(t, signature)

	signature, ok = attempts.try(func() ([]byte, error) { return []byte("sig"), nil })
	require.True(t, ok, "the next identity signs")
	assert.Equal(t, []byte("sig"), signature)
}

// TestSignAttempts_KeepsEveryFailure: when no identity signs, the approval a user has to
// give must not be hidden behind the failure of a later identity.
func TestSignAttempts_KeepsEveryFailure(t *testing.T) {
	var attempts signAttempts
	assert.NoError(t, attempts.err(), "no attempts, no error")

	attempts.try(func() ([]byte, error) { return nil, errNeedsApprovalForTest })
	attempts.try(func() ([]byte, error) { return nil, errors.New("key is gone") })

	err := attempts.err()
	require.Error(t, err)
	assert.ErrorIs(t, err, errNeedsApprovalForTest, "the earlier approval error survives the later failure")
	assert.ErrorContains(t, err, "key is gone")
}
