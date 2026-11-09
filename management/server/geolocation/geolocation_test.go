package geolocation

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
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
	head, download, update := headRequestTimeout, downloadTimeout, updateTimeout
	headRequestTimeout, downloadTimeout, updateTimeout = 100*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() {
		headRequestTimeout, downloadTimeout, updateTimeout = head, download, update
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

func TestNewGeolocation_UsesExistingDatabasesOffline(t *testing.T) {
	dataDir := t.TempDir()
	require.NoError(t, util.CopyFileContents(mmdbPath, path.Join(dataDir, filepath.Base(mmdbPath))))
	require.NoError(t, util.CopyFileContents("../testdata/geonames_20240305.db", path.Join(dataDir, "geonames_20240305.db")))

	geo, err := NewGeolocation(context.Background(), dataDir, false)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, geo.Stop())
	}()

	record, err := geo.Lookup(net.ParseIP("89.160.20.128"))
	require.NoError(t, err)
	assert.Equal(t, "SE", record.Country.ISOCode, "the MaxMind database must be opened")
	countries, err := geo.GetAllCountries()
	require.NoError(t, err)
	assert.NotEmpty(t, countries, "the geonames database must be opened")
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
}

func TestEnsureDatabase(t *testing.T) {
	const (
		oldFile = "GeoLite2-City_20240305.mmdb"
		newFile = "GeoLite2-City_20991231.mmdb"
	)
	// Refuses an existing file, like the geonames import that would append to it.
	writeNew := func(_ context.Context, dir, name string) error {
		f, err := os.OpenFile(path.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, err = f.WriteString("new")
		return errors.Join(err, f.Close())
	}
	writePartial := func(_ context.Context, dir, name string) error {
		require.NoError(t, os.WriteFile(path.Join(dir, name), []byte("partial"), 0o600))
		return errors.New("connection reset")
	}
	// A download that only ends when its context does, like a mirror stalling mid-body.
	stall := func(ctx context.Context, _, _ string) error {
		<-ctx.Done()
		return ctx.Err()
	}

	tests := []struct {
		name       string
		existing   bool
		leftover   bool   // partial download left by a crash
		mirrorFile string // filename the mirror announces, empty when the mirror fails
		autoUpdate bool
		download   downloadFunc
		want       string
		wantFiles  []string
	}{
		{name: "update check fails, existing database is used", existing: true, autoUpdate: true, want: oldFile, wantFiles: []string{oldFile}},
		{name: "download fails, existing database is used and partial file removed", existing: true, mirrorFile: "GeoLite2-City_20991231.tar.gz", autoUpdate: true, download: writePartial, want: oldFile, wantFiles: []string{oldFile}},
		{name: "successful update removes the old database", existing: true, mirrorFile: "GeoLite2-City_20991231.tar.gz", autoUpdate: true, download: writeNew, want: newFile, wantFiles: []string{newFile}},
		{name: "stalled download falls back to existing database", existing: true, mirrorFile: "GeoLite2-City_20991231.tar.gz", autoUpdate: true, download: stall, want: oldFile, wantFiles: []string{oldFile}},
		{name: "partial file left by a crash is replaced", existing: true, leftover: true, mirrorFile: "GeoLite2-City_20991231.tar.gz", autoUpdate: true, download: writeNew, want: newFile, wantFiles: []string{newFile}},
		{name: "no database and update check fails", autoUpdate: true},
		{name: "auto update off uses existing database without a download", existing: true, want: oldFile, wantFiles: []string{oldFile}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shortTimeouts(t)
			dataDir := t.TempDir()
			if tt.existing {
				require.NoError(t, util.CopyFileContents(mmdbPath, path.Join(dataDir, oldFile)))
			}
			if tt.leftover {
				require.NoError(t, os.WriteFile(path.Join(dataDir, newFile+".tmp"), []byte("partial"), 0o600))
			}
			mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.mirrorFile == "" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.Header().Set("Content-Disposition", "attachment; filename="+tt.mirrorFile)
			}))
			defer mirror.Close()
			download := tt.download
			if download == nil {
				download = func(context.Context, string, string) error {
					t.Error("download must not be attempted")
					return nil
				}
			}

			got, err := ensureDatabase(context.Background(), dataDir, mmdbPattern, mirror.URL, tt.autoUpdate, download)
			if tt.want == "" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.want, got, "database in use")

			var files []string
			for _, f := range getExistingDatabases(filepath.Join(dataDir, "*")) {
				files = append(files, filepath.Base(f))
			}
			assert.ElementsMatch(t, tt.wantFiles, files, "files left in the data directory")
		})
	}
}
