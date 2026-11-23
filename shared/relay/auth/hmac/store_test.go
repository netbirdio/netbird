package hmac

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenStore_KindFollowsTheLastUpdate(t *testing.T) {
	var s TokenStore

	require.NoError(t, s.UpdateToken(&Token{Payload: "payload", Signature: "c2ln"}))
	_, isAuthToken := s.Credentials()
	assert.False(t, isAuthToken, "a legacy token must not be presented as the auth token")

	authToken := []byte{2, 1, 2, 3}
	require.NoError(t, s.UpdateAuthToken(authToken))
	authToken[0] = 9
	token, isAuthToken := s.Credentials()
	assert.True(t, isAuthToken, "the auth token must be presented as the auth token")
	assert.Equal(t, []byte{2, 1, 2, 3}, token, "the store must keep its own copy of the auth token")

	assert.Error(t, s.UpdateAuthToken(nil), "an empty auth token must be refused")
	_, isAuthToken = s.Credentials()
	assert.True(t, isAuthToken, "a refused auth token must leave the current one in place")

	// Management turning the feature off sends a legacy token again.
	require.NoError(t, s.UpdateToken(&Token{Payload: "payload", Signature: "c2ln"}))
	_, isAuthToken = s.Credentials()
	assert.False(t, isAuthToken, "a legacy token must replace the auth token")
}
