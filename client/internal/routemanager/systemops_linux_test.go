//go:build !android

package routemanager

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEntryExists(t *testing.T) {
	tempDir := t.TempDir()
	tempFilePath := fmt.Sprintf("%s/rt_tables", tempDir)

	content := []string{
		"1000 reserved",
		fmt.Sprintf("%d %s", NetbirdVPNTableID, NetbirdVPNTableName),
		"9999 other_table",
	}
	require.NoError(t, os.WriteFile(tempFilePath, []byte(strings.Join(content, "\n")), 0644))

	file, err := os.Open(tempFilePath)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, file.Close())
	}()

	tests := []struct {
		name        string
		id          int
		shouldExist bool
		err         error
	}{
		{
			name:        "ExistsWithNetbirdPrefix",
			id:          7120,
			shouldExist: true,
			err:         nil,
		},
		{
			name:        "ExistsWithDifferentName",
			id:          1000,
			shouldExist: true,
			err:         ErrTableIDExists,
		},
		{
			name:        "DoesNotExist",
			id:          1234,
			shouldExist: false,
			err:         nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exists, err := entryExists(file, tc.id)
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.shouldExist, exists)
		})
	}
}
