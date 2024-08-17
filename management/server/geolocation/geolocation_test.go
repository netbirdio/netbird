package geolocation

import (
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/util"
)

// from https://github.com/maxmind/MaxMind-DB/blob/main/test-data/GeoLite2-City-Test.mmdb
var (
	mmdbPath     = "../testdata/GeoLite2-City-Test.mmdb"
	mmdbFilename = "GeoLite2-City.mmdb"
)

func TestGeoLite_Lookup(t *testing.T) {
	tempDir := t.TempDir()
	filename := path.Join(tempDir, mmdbFilename)
	err := util.CopyFileContents(mmdbPath, filename)
	assert.NoError(t, err)
	defer func() {
		err := os.Remove(filename)
		if err != nil {
			t.Errorf("os.Remove: %s", err)
		}
	}()

	db, err := openDB(mmdbPath)
	assert.NoError(t, err)

	geo := &Geolocation{
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

func TestGeolite_Name_Lookup(t *testing.T) {
	var mmdbFile string
	var geonamesFile string

	var mmdbRegexp *regexp.Regexp = regexp.MustCompile(strings.Replace(mmdbPattern, "*", "\\d{8}", 1))
	var geonamesdbRegexp *regexp.Regexp = regexp.MustCompile(strings.Replace(geonamesdbPattern, "*", "\\d{8}", 1))

	tempDir := t.TempDir()
	filename := path.Join(tempDir, mmdbFilename)
	// if auto-update is disabled and there is no existing database,
	// defaults to the old database names
	mmdbFile, geonamesFile = GetMaxMindFilenames(tempDir, false)
	assert.Equal(t, oldMMDBFilename, mmdbFile)
	assert.Equal(t, oldGeoNamesDBFilename, geonamesFile)

	mmdbFile, geonamesFile = GetMaxMindFilenames(tempDir, true)
	assert.Regexp(t, mmdbRegexp, mmdbFile)
	assert.Regexp(t, geonamesdbRegexp, geonamesFile)

	err := util.CopyFileContents(mmdbPath, filename)
	assert.NoError(t, err)
	// if auto-update is disabled and an existing database is found,
	// returns the name of the existing database
	mmdbFile, _ = GetMaxMindFilenames(tempDir, false)
	assert.Equal(t, mmdbFilename, mmdbFile)

	mmdbFile, _ = GetMaxMindFilenames(tempDir, true)
	assert.Regexp(t, mmdbRegexp, mmdbFile)
}