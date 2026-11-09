//go:build !windows && !ios && !android

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/configs"
)

// The Windows equivalent of this is the ACL check in
// elevate.CheckOnlyOwnerWritable, covered by that package's own tests; here the
// point is that loadServiceParams asks the question at all.
func TestLoadServiceParams_RefusesWorldWritableFile(t *testing.T) {
	tmpDir := t.TempDir()

	original := configs.StateDir
	t.Cleanup(func() { configs.StateDir = original })
	configs.StateDir = tmpDir

	path := filepath.Join(tmpDir, serviceParamsFile)
	require.NoError(t, os.WriteFile(path, []byte(`{"log_level":"debug"}`), 0o666))
	// WriteFile is subject to the umask, so set the bits that matter explicitly.
	require.NoError(t, os.Chmod(path, 0o666))

	params, err := loadServiceParams()
	require.Error(t, err, "a service.json anyone can rewrite must not be trusted")
	assert.Nil(t, params)

	require.NoError(t, os.Chmod(path, 0o600))
	params, err = loadServiceParams()
	require.NoError(t, err)
	require.NotNil(t, params)
	assert.Equal(t, "debug", params.LogLevel)
}

func TestLoadServiceParams_RefusesWorldWritableDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	stateDir := filepath.Join(tmpDir, "state")
	require.NoError(t, os.Mkdir(stateDir, 0o777))
	require.NoError(t, os.Chmod(stateDir, 0o777))

	original := configs.StateDir
	t.Cleanup(func() { configs.StateDir = original })
	configs.StateDir = stateDir

	require.NoError(t, os.WriteFile(filepath.Join(stateDir, serviceParamsFile), []byte(`{}`), 0o600))

	params, err := loadServiceParams()
	require.Error(t, err, "a service.json in a directory anyone can replace entries in must not be trusted")
	assert.Nil(t, params)
}
