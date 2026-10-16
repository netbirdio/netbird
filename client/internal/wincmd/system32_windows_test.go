package wincmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystem32IgnoresPATH(t *testing.T) {
	// A directory holding something that would win a PATH lookup, in front of
	// everything else: the daemon runs as LocalSystem, so a PATH entry must not
	// be able to decide what it executes.
	planted := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(planted, "netsh.exe"), []byte("not really netsh"), 0o600))
	t.Setenv("PATH", planted+string(os.PathListSeparator)+os.Getenv("PATH"))

	got := System32("netsh")

	assert.True(t, filepath.IsAbs(got), "the path must be absolute, got %q", got)
	assert.NotContains(t, got, planted, "a PATH entry must not be consulted")
	assert.True(t, strings.EqualFold(filepath.Base(got), "netsh.exe"), "unexpected file name in %q", got)

	// The system directory is what Windows reports it to be, not %SystemRoot%,
	// which the same caller could have set alongside PATH.
	t.Setenv("SystemRoot", planted)
	assert.Equal(t, got, System32("netsh"), "%SystemRoot% must not move the lookup")
}
