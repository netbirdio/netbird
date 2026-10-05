package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShortExecPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Net Bird Dir")
	require.NoError(t, os.Mkdir(dir, 0755))
	path := filepath.Join(dir, "netbird.exe")
	require.NoError(t, os.WriteFile(path, nil, 0644))

	short, err := shortExecPath(path)
	require.NoError(t, err)
	if strings.Contains(short, " ") {
		t.Skipf("8.3 short names are disabled on this volume: %s", short)
	}

	longInfo, err := os.Stat(path)
	require.NoError(t, err)
	shortInfo, err := os.Stat(short)
	require.NoError(t, err)
	assert.True(t, os.SameFile(longInfo, shortInfo), "short path %s must point to %s", short, path)
}
