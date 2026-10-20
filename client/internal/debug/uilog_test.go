package debug

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/configs"
)

// bundleEntries generates a bundle with the given generator and returns the
// set of entry names in the resulting archive.
func bundleEntries(t *testing.T, g *BundleGenerator) map[string]struct{} {
	t.Helper()

	path, err := g.Generate()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(path) })

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)

	names := make(map[string]struct{}, len(zr.File))
	for _, f := range zr.File {
		names[f.Name] = struct{}{}
	}
	return names
}

func TestBundleIncludesUILogWhenOpenerAllows(t *testing.T) {
	path := filepath.Join(t.TempDir(), configs.UILogFile)
	require.NoError(t, os.WriteFile(path, []byte("gui log"), 0600))

	g := NewBundleGenerator(GeneratorDependencies{
		UILogPath:   path,
		UILogOpener: openLogFile,
	}, BundleConfig{})

	require.Contains(t, bundleEntries(t, g), configs.UILogFile)
}

// A UILogOpener that refuses (as the ownership check does for a foreign file)
// keeps the UI log out of the bundle without failing bundle generation.
func TestBundleExcludesUILogWhenOpenerRefuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), configs.UILogFile)
	require.NoError(t, os.WriteFile(path, []byte("secret"), 0600))

	g := NewBundleGenerator(GeneratorDependencies{
		UILogPath: path,
		UILogOpener: func(string) (*os.File, error) {
			return nil, fmt.Errorf("not owned by the caller")
		},
	}, BundleConfig{})

	require.NotContains(t, bundleEntries(t, g), configs.UILogFile)
}
