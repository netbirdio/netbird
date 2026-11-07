//go:build windows

package coexist

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddressChangesRegisters(t *testing.T) {
	changes, stop, err := addressChanges()
	require.NoError(t, err)
	require.NotNil(t, changes, "a change channel")
	stop()
}
