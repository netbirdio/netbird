package cmd

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

// Omitting --owner is only allowed where the invoking user can be recovered.
// Everywhere else the admin names the owner rather than having one guessed.
func TestDefaultClaimOwner(t *testing.T) {
	got, err := defaultClaimOwner()

	switch {
	case runtime.GOOS == "windows":
		require.Error(t, err, "Windows keeps no record of who asked for elevation")
		assert.Contains(t, err.Error(), "--owner")
	case profilemanager.IsPlainRoot():
		require.Error(t, err, "plain root has no invoking user to act for")
		assert.Contains(t, err.Error(), "--owner")
	default:
		require.NoError(t, err)
		assert.NotEmpty(t, got)
	}
}
