package geolocation

import (
	"os"
	"path"
	"testing"

	"github.com/netbirdio/netbird/util"
	"github.com/stretchr/testify/assert"
)

// from https://github.com/maxmind/MaxMind-DB/blob/main/test-data/GeoLite2-City-Test.mmdb
var mmdbPath = "../testdata/GeoLite2-City-Test.mmdb"

func TestGeoLite_Lookup(t *testing.T) {
	tempDir := t.TempDir()
	filename := path.Join(tempDir, mmdbFileName)
	err := util.CopyFileContents(mmdbPath, filename)
	assert.NoError(t, err)
	defer func() {
		err := os.Remove(filename)
		if err != nil {
			t.Errorf("os.Remove: %s", err)
		}
	}()

	geo, err := NewGeolocation(tempDir)
	assert.NoError(t, err)
	assert.NotNil(t, geo)
	defer func() {
		err = geo.Stop()
		if err != nil {
			t.Errorf("geo.Stop: %s", err)
		}
	}()

	record, err := geo.Lookup("89.160.20.128")
	assert.NoError(t, err)
	assert.NotNil(t, record)
	assert.Equal(t, "SE", record.Country.ISOCode)
	assert.Equal(t, uint(2661886), record.Country.GeonameID)
	assert.Equal(t, "Linköping", record.City.Names.En)
	assert.Equal(t, uint(2694762), record.City.GeonameID)
	assert.Equal(t, "EU", record.Continent.Code)
	assert.Equal(t, uint(6255148), record.Continent.GeonameID)

	_, err = geo.Lookup("589.160.20.128")
	assert.Error(t, err)
}
