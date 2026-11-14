package geolocation

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/util"
)

// from https://github.com/maxmind/MaxMind-DB/blob/main/test-data/GeoLite2-City-Test.mmdb
var mmdbPath = "../testdata/GeoLite2-City_20240305.mmdb"

func TestGeoLite_Lookup(t *testing.T) {
	tempDir := t.TempDir()
	filename := path.Join(tempDir, filepath.Base(mmdbPath))
	err := util.CopyFileContents(mmdbPath, filename)
	assert.NoError(t, err)

	db, err := openDB(filename)
	assert.NoError(t, err)

	geo := &geolocationImpl{
		mux:    sync.RWMutex{},
		db:     db,
		stopCh: make(chan struct{}),
	}
	assert.NotNil(t, geo)
	defer func() {
		err = geo.Stop()
		if err != nil {
			t.Errorf("geo.Stop: %s", err)
		}
	}()

	record, err := geo.Lookup(net.ParseIP("89.160.20.128"))
	assert.NoError(t, err)
	assert.NotNil(t, record)
	assert.Equal(t, "SE", record.Country.ISOCode)
	assert.Equal(t, uint(2661886), record.Country.GeonameID)
	assert.Equal(t, "Linköping", record.City.Names.En)
	assert.Equal(t, uint(2694762), record.City.GeonameID)
	assert.Equal(t, "EU", record.Continent.Code)
	assert.Equal(t, uint(6255148), record.Continent.GeonameID)
}

// shortTimeouts makes stalled requests fail fast for the duration of a test.
func shortTimeouts(t *testing.T) {
	t.Helper()
	head, idle := headRequestTimeout, downloadIdleTimeout
	headRequestTimeout, downloadIdleTimeout = 100*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() {
		headRequestTimeout, downloadIdleTimeout = head, idle
	})
}

// stalledServer accepts requests but never answers them, like a blocked connection.
func stalledServer(t *testing.T, writeHeader bool) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if writeHeader {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	return srv
}

func TestDownloadFile_WritesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("database"))
	}))
	defer srv.Close()
	target := path.Join(t.TempDir(), "db")

	require.NoError(t, downloadFile(context.Background(), srv.URL, target))
	content, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "database", string(content), "downloaded file content")
}

func TestGetFilenameFromURL_StalledServerTimesOut(t *testing.T) {
	shortTimeouts(t)
	srv := stalledServer(t, false)

	start := time.Now()
	_, err := getFilenameFromURL(context.Background(), srv.URL)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second, "a stalled lookup must give up instead of blocking startup")
}

func TestDownloadFile_StalledBodyTimesOut(t *testing.T) {
	shortTimeouts(t)
	srv := stalledServer(t, true)

	start := time.Now()
	err := downloadFile(context.Background(), srv.URL, path.Join(t.TempDir(), "db"))
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second, "a stalled download must give up instead of blocking startup")
	assert.Contains(t, err.Error(), "no data received", "the error must name the stall")
}

func TestDownloadFile_SlowDownloadCompletes(t *testing.T) {
	shortTimeouts(t)
	// Each chunk arrives within the idle timeout, the whole body takes several times longer.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		for range 20 {
			_, _ = w.Write([]byte("x"))
			w.(http.Flusher).Flush()
			time.Sleep(20 * time.Millisecond)
		}
	}))
	defer srv.Close()
	target := path.Join(t.TempDir(), "db")

	require.NoError(t, downloadFile(context.Background(), srv.URL, target))
	content, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, strings.Repeat("x", 20), string(content), "a slow download that keeps sending data must finish")
}

func TestIdleReader_CapsReadSize(t *testing.T) {
	idle := time.NewTimer(time.Hour)
	defer idle.Stop()
	r := &idleReader{r: bytes.NewReader(make([]byte, 2*idleReadSize)), idle: idle}

	n, err := r.Read(make([]byte, 2*idleReadSize))
	require.NoError(t, err)
	assert.Equal(t, idleReadSize, n, "a single read must not exceed idleReadSize")
}
