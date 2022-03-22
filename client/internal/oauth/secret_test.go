package oauth

import (
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestSecret(t *testing.T) {
	// this test is not ready to run as part of our ci/cd
	// todo fix testing
	if os.Getenv("GITHUB_ACTIONS") != "" {
		t.Skip("skipping testing in github actions")
	}

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
