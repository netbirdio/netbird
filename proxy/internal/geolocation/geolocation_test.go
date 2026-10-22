package geolocation

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fixture from https://github.com/maxmind/MaxMind-DB/blob/main/test-data/GeoLite2-City-Test.mmdb
const fixturePath = "../../../management/server/testdata/GeoLite2-City_20240305.mmdb"

var testAddr = netip.MustParseAddr("89.160.20.128")

type fakeRegistry struct {
	tarGZ    []byte
	sum      string
	version  atomic.Value
	failures atomic.Int32
	gets     atomic.Int32
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	mmdb, err := os.ReadFile(fixturePath)
	require.NoError(t, err)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "GeoLite2-City_x/" + mmdbInnerName, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(mmdb))}))
	_, err = tw.Write(mmdb)
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	f := &fakeRegistry{tarGZ: buf.Bytes(), sum: fmt.Sprintf("%x", sha256.Sum256(buf.Bytes()))}
	f.version.Store("20240305")

	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)

	origTar, origSum, origBackoff := mmdbTarGZURL, mmdbSha256URL, initialBackoff
	mmdbTarGZURL = srv.URL + "/db.tar.gz"
	mmdbSha256URL = srv.URL + "/db.tar.gz.sha256"
	initialBackoff = 10 * time.Millisecond
	t.Cleanup(func() {
		mmdbTarGZURL, mmdbSha256URL, initialBackoff = origTar, origSum, origBackoff
	})
	return f
}

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	if f.failures.Load() > 0 {
		f.failures.Add(-1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=GeoLite2-City_%s.tar.gz", f.version.Load()))
	if r.Method == http.MethodHead {
		return
	}
	f.gets.Add(1)
	if r.URL.Path == "/db.tar.gz.sha256" {
		_, _ = fmt.Fprintf(w, "%s  GeoLite2-City.tar.gz\n", f.sum)
		return
	}
	_, _ = w.Write(f.tarGZ)
}

func newTestLookup(t *testing.T, dir string) *Lookup {
	t.Helper()
	l, err := NewLookup(log.New(), dir, time.Hour)
	require.NoError(t, err)
	require.NotNil(t, l)
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestNewLookup_BackgroundDownload(t *testing.T) {
	newFakeRegistry(t)
	dir := t.TempDir()

	start := time.Now()
	l := newTestLookup(t, dir)
	assert.Less(t, time.Since(start), 5*time.Second)

	require.Eventually(t, l.Available, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, "SE", l.LookupAddr(testAddr).CountryCode)
	assert.FileExists(t, filepath.Join(dir, "GeoLite2-City_20240305.mmdb"))
}

func TestNewLookup_NotAvailableBeforeDownload(t *testing.T) {
	f := newFakeRegistry(t)
	f.failures.Store(1 << 20)

	l := newTestLookup(t, t.TempDir())
	assert.False(t, l.Available())
	assert.Equal(t, Result{}, l.LookupAddr(testAddr))
}

func TestNewLookup_RetriesAfterFailure(t *testing.T) {
	f := newFakeRegistry(t)
	f.failures.Store(3)

	l := newTestLookup(t, t.TempDir())
	require.Eventually(t, l.Available, 5*time.Second, 10*time.Millisecond)
}

func TestNewLookup_LoadsLocalFileSynchronously(t *testing.T) {
	f := newFakeRegistry(t)
	f.failures.Store(1 << 20)
	dir := t.TempDir()
	mmdb, err := os.ReadFile(fixturePath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "GeoLite2-City_20240305.mmdb"), mmdb, 0o644))

	l := newTestLookup(t, dir)
	assert.True(t, l.Available())
}

func TestNewLookup_CorruptFileRemovedAndRedownloaded(t *testing.T) {
	newFakeRegistry(t)
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "GeoLite2-City_20230101.mmdb")
	require.NoError(t, os.WriteFile(corrupt, []byte("garbage"), 0o644))

	l := newTestLookup(t, dir)
	require.Eventually(t, l.Available, 5*time.Second, 10*time.Millisecond)
	assert.NoFileExists(t, corrupt)
}

func TestLookup_UpdateSwapsToNewerVersion(t *testing.T) {
	f := newFakeRegistry(t)
	dir := t.TempDir()
	l := newTestLookup(t, dir)
	require.Eventually(t, l.Available, 5*time.Second, 10*time.Millisecond)

	older := filepath.Join(dir, "GeoLite2-City_20240101.mmdb")
	newerOther := filepath.Join(dir, "GeoLite2-City_20991231.mmdb")
	require.NoError(t, os.WriteFile(older, []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(newerOther, []byte("x"), 0o644))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					assert.Equal(t, "SE", l.LookupAddr(testAddr).CountryCode)
				}
			}
		}()
	}

	f.version.Store("20240401")
	require.NoError(t, l.update(t.Context()))
	close(stop)
	wg.Wait()

	assert.Equal(t, "SE", l.LookupAddr(testAddr).CountryCode)
	assert.FileExists(t, filepath.Join(dir, "GeoLite2-City_20240401.mmdb"))
	assert.NoFileExists(t, filepath.Join(dir, "GeoLite2-City_20240305.mmdb"))
	assert.NoFileExists(t, older)
	assert.FileExists(t, newerOther)
}

func TestLookup_UpdateSameVersionDoesNotDownload(t *testing.T) {
	f := newFakeRegistry(t)
	l := newTestLookup(t, t.TempDir())
	require.Eventually(t, l.Available, 5*time.Second, 10*time.Millisecond)

	before := f.gets.Load()
	require.NoError(t, l.update(t.Context()))
	assert.Equal(t, before, f.gets.Load())
}

func TestLookup_CloseStopsGoroutine(t *testing.T) {
	f := newFakeRegistry(t)
	f.failures.Store(1 << 20)
	l, err := NewLookup(log.New(), t.TempDir(), time.Hour)
	require.NoError(t, err)

	require.NoError(t, l.Close())
	select {
	case <-l.done:
	default:
		t.Fatal("background goroutine still running after Close")
	}
	assert.False(t, l.Available())
}

func TestLookup_NilSafe(t *testing.T) {
	var l *Lookup
	assert.NoError(t, l.Close())
	assert.False(t, l.Available())
}
