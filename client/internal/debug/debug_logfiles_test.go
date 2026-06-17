package debug

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestAddRotatedLogFiles_PicksUpAllVariants asserts that the rotated-log
// glob picks up logs rotated by timberjack (gzipped) and by logrotate (plain
// and gzipped), and skips unrelated files.
func TestAddRotatedLogFiles_PicksUpAllVariants(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "client.log"), "active log\n")
	writeFile(t, filepath.Join(dir, "other.log"), "unrelated\n")

	timberjackRotated := "client-2026-05-21T10-30-45.000.log.gz"
	writeGzFile(t, filepath.Join(dir, timberjackRotated), "timberjack rotated content\n")

	logrotatePlain := "client.log.1"
	writeFile(t, filepath.Join(dir, logrotatePlain), "logrotate plain content\n")

	logrotateGz := "client.log.2.gz"
	writeGzFile(t, filepath.Join(dir, logrotateGz), "logrotate gz content\n")

	names := runAddRotatedLogFiles(t, dir, 10)

	require.Contains(t, names, timberjackRotated, "timberjack rotated file should be in bundle")
	require.Contains(t, names, logrotatePlain, "logrotate plain rotated file should be in bundle")
	require.Contains(t, names, logrotateGz, "logrotate gzipped rotated file should be in bundle")
	require.NotContains(t, names, "client.log", "active log should not be added by addRotatedLogFiles")
	require.NotContains(t, names, "other.log", "unrelated files should not be in bundle")
}

// TestAddRotatedLogFiles_RespectsLogFileCount asserts that only the newest
// logFileCount rotated files are bundled, ordered by mtime.
func TestAddRotatedLogFiles_RespectsLogFileCount(t *testing.T) {
	dir := t.TempDir()

	oldest := filepath.Join(dir, "client.log.3")
	middle := filepath.Join(dir, "client.log.2")
	newest := filepath.Join(dir, "client.log.1")
	writeFile(t, oldest, "old\n")
	writeFile(t, middle, "mid\n")
	writeFile(t, newest, "new\n")

	now := time.Now()
	require.NoError(t, os.Chtimes(oldest, now.Add(-2*time.Hour), now.Add(-2*time.Hour)))
	require.NoError(t, os.Chtimes(middle, now.Add(-1*time.Hour), now.Add(-1*time.Hour)))
	require.NoError(t, os.Chtimes(newest, now, now))

	names := runAddRotatedLogFiles(t, dir, 2)

	require.Contains(t, names, "client.log.1")
	require.Contains(t, names, "client.log.2")
	require.NotContains(t, names, "client.log.3", "oldest file should be dropped when logFileCount=2")
}

// runAddRotatedLogFiles calls addRotatedLogFiles against a fresh in-memory
// zip writer and returns the set of entry names that ended up in the archive.
func runAddRotatedLogFiles(t *testing.T, dir string, logFileCount uint32) map[string]struct{} {
	t.Helper()

	var buf bytes.Buffer
	g := &BundleGenerator{
		archive:      zip.NewWriter(&buf),
		logFileCount: logFileCount,
	}
	g.addRotatedLogFiles(dir)
	require.NoError(t, g.archive.Close())

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)

	names := make(map[string]struct{}, len(zr.File))
	for _, f := range zr.File {
		names[f.Name] = struct{}{}
	}
	return names
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func writeGzFile(t *testing.T, path, content string) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err := io.WriteString(gw, content)
	require.NoError(t, err)
	require.NoError(t, gw.Close())
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o644))
}
