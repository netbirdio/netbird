package oauth

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSecret(t *testing.T) {
	key := "testing"
	value := "1234"
	err := SetSecret(key, value)
	require.NoError(t, err, "should set secret")

	v, err := GetSecret(key)
	require.NoError(t, err, "should retrieve secret")
	require.Equal(t, value, v, "values should match")

	err = DeleteSecret(key)
	require.NoError(t, err, "should delete secret")
}
