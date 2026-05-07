package rosenpass

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindRandomAvailableUDPPort(t *testing.T) {
	port, err := findRandomAvailableUDPPort()
	require.NoError(t, err)
	require.Greater(t, port, 0)
	require.LessOrEqual(t, port, 65535)
}
