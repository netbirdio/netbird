package geolocation

import (
	"context"
	"errors"
	"net"
	"os"
	"path"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/util"
)

// from https://github.com/maxmind/MaxMind-DB/blob/main/test-data/GeoLite2-City-Test.mmdb
var mmdbPath = "../testdata/GeoLite2-City_20240305.mmdb"

var geonamesdbPath = "../testdata/geonames_20240305.db"

func copyTestDatabases(t *testing.T, dir, mmdbFile, geonamesDbFile string) {
	t.Helper()
	require.NoError(t, util.CopyFileContents(mmdbPath, path.Join(dir, mmdbFile)))
	require.NoError(t, util.CopyFileContents(geonamesdbPath, path.Join(dir, geonamesDbFile)))
}

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
		cancel: func() {},
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

func TestNewGeolocation_LocalDatabasesReady(t *testing.T) {
	tempDir := t.TempDir()
	copyTestDatabases(t, tempDir, filepath.Base(mmdbPath), filepath.Base(geonamesdbPath))

	geo := NewGeolocation(context.Background(), tempDir, false, 0)
	t.Cleanup(func() { _ = geo.Stop() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, geo.WaitReady(ctx), "local databases must be loaded before NewGeolocation returns")

	record, err := geo.Lookup(net.ParseIP("89.160.20.128"))
	require.NoError(t, err)
	assert.Equal(t, "SE", record.Country.ISOCode)

	countries, err := geo.GetAllCountries()
	require.NoError(t, err)
	assert.NotEmpty(t, countries)
}

func TestWaitReady_NotLoaded(t *testing.T) {
	geoCtx, geoCancel := context.WithCancel(context.Background())
	geo := &geolocationImpl{
		ready:  make(chan struct{}),
		done:   geoCtx.Done(),
		cancel: geoCancel,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, geo.WaitReady(ctx), context.Canceled)

	_, err := geo.Lookup(net.ParseIP("89.160.20.128"))
	assert.Error(t, err, "lookup must fail before a database is loaded")
	_, err = geo.GetAllCountries()
	assert.ErrorIs(t, err, errLocationDBNotLoaded)

	require.NoError(t, geo.Stop())
	assert.ErrorIs(t, geo.WaitReady(context.Background()), ErrStopped)
}

func TestOpen_SwapsDatabasesDuringLookups(t *testing.T) {
	tempDir := t.TempDir()
	copyTestDatabases(t, tempDir, "GeoLite2-City_20240305.mmdb", "geonames_20240305.db")
	copyTestDatabases(t, tempDir, "GeoLite2-City_20240306.mmdb", "geonames_20240306.db")

	geo := &geolocationImpl{
		dataDir: tempDir,
		ready:   make(chan struct{}),
		cancel:  func() {},
	}
	_, err := geo.open(context.Background(), "GeoLite2-City_20240305.mmdb", "geonames_20240305.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = geo.Stop() })

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				record, err := geo.Lookup(net.ParseIP("89.160.20.128"))
				if !assert.NoError(t, err) || !assert.Equal(t, "SE", record.Country.ISOCode) {
					return
				}
				_, err = geo.GetCitiesByCountry("SE")
				if !assert.NoError(t, err) {
					return
				}
			}
		})
	}

	_, err = geo.open(context.Background(), "GeoLite2-City_20240306.mmdb", "geonames_20240306.db")
	require.NoError(t, err)
	close(stop)
	wg.Wait()

	geo.mux.RLock()
	defer geo.mux.RUnlock()
	assert.Equal(t, "GeoLite2-City_20240306.mmdb", geo.mmdbFile)
	assert.Equal(t, "geonames_20240306.db", geo.geonamesDbFile)
}

func TestWriteAtomically(t *testing.T) {
	tempDir := t.TempDir()

	err := writeAtomically(tempDir, "geonames_20240306.db", func(tmpFile string) error {
		require.NoError(t, os.WriteFile(path.Join(tempDir, tmpFile), []byte("partial"), 0o600))
		return errors.New("import failed")
	})
	require.Error(t, err)
	entries, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "a failed write must leave neither the target nor a temporary file")

	err = writeAtomically(tempDir, "geonames_20240306.db", func(tmpFile string) error {
		return os.WriteFile(path.Join(tempDir, tmpFile), []byte("complete"), 0o600)
	})
	require.NoError(t, err)
	content, err := os.ReadFile(path.Join(tempDir, "geonames_20240306.db"))
	require.NoError(t, err)
	assert.Equal(t, "complete", string(content))
	entries, err = os.ReadDir(tempDir)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

func TestCleanupOldDatabases_KeepsNewer(t *testing.T) {
	tempDir := t.TempDir()
	for _, name := range []string{"GeoLite2-City_20240301.mmdb", "GeoLite2-City_20240305.mmdb", "GeoLite2-City_20240310.mmdb"} {
		require.NoError(t, os.WriteFile(path.Join(tempDir, name), nil, 0o600))
	}

	require.NoError(t, cleanupOldDatabases(context.Background(), filepath.Join(tempDir, mmdbPattern), "GeoLite2-City_20240305.mmdb"))

	assert.NoFileExists(t, path.Join(tempDir, "GeoLite2-City_20240301.mmdb"))
	assert.FileExists(t, path.Join(tempDir, "GeoLite2-City_20240305.mmdb"))
	assert.FileExists(t, path.Join(tempDir, "GeoLite2-City_20240310.mmdb"), "a newer database stored by another instance must be kept")
}
