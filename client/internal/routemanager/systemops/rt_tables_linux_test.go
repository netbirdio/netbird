//go:build linux && !android

package systemops

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

func TestRegisterRoutingTableName(t *testing.T) {
	entry := fmt.Sprintf("%d\t%s\n", NetbirdVPNTableID, NetbirdVPNTableName)

	t.Run("CreatesDropInAndDirectory", func(t *testing.T) {
		dir := t.TempDir()
		legacy := dir + "/rt_tables"
		dropIn := dir + "/rt_tables.d/netbird.conf"

		require.NoError(t, registerRoutingTableName(legacy, dropIn))

		data, err := os.ReadFile(dropIn)
		require.NoError(t, err)
		assert.Equal(t, entry, string(data), "drop-in should hold only the netbird entry")
		assert.NoFileExists(t, legacy, "the legacy rt_tables file must not be created")
	})

	t.Run("SkipsWhenLegacyHasEntry", func(t *testing.T) {
		dir := t.TempDir()
		legacy := dir + "/rt_tables"
		dropIn := dir + "/rt_tables.d/netbird.conf"
		require.NoError(t, os.WriteFile(legacy, []byte("255\tlocal\n"+entry), 0o644))

		require.NoError(t, registerRoutingTableName(legacy, dropIn))

		assert.NoFileExists(t, dropIn, "an entry written by an older release is enough")
	})

	t.Run("KeepsExistingDropIn", func(t *testing.T) {
		dir := t.TempDir()
		dropIn := dir + "/rt_tables.d/netbird.conf"
		require.NoError(t, os.MkdirAll(dir+"/rt_tables.d", 0o755))
		require.NoError(t, os.WriteFile(dropIn, []byte(entry), 0o644))

		require.NoError(t, registerRoutingTableName(dir+"/rt_tables", dropIn))

		data, err := os.ReadFile(dropIn)
		require.NoError(t, err)
		assert.Equal(t, entry, string(data))
	})

	t.Run("RejectsIDTakenByAnotherName", func(t *testing.T) {
		dir := t.TempDir()
		legacy := dir + "/rt_tables"
		dropIn := dir + "/rt_tables.d/netbird.conf"
		require.NoError(t, os.WriteFile(legacy, []byte(fmt.Sprintf("%d\tother\n", NetbirdVPNTableID)), 0o644))

		err := registerRoutingTableName(legacy, dropIn)

		assert.ErrorIs(t, err, ErrTableIDExists)
		assert.NoFileExists(t, dropIn)
	})
}
