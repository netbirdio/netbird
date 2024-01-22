package geolite

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// from https://github.com/maxmind/MaxMind-DB/blob/main/test-data/GeoLite2-City-Test.mmdb
var path = "../testdata/GeoLite2-City-Test.mmdb"

func TestGeoLite_Lookup(t *testing.T) {
	geo, err := NewGeoLite(path)
	assert.NoError(t, err)
	assert.NotNil(t, geo)

	record, err := geo.Lookup("89.160.20.128")
	assert.NoError(t, err)
	assert.NotNil(t, record)
	assert.Equal(t, "SE", record.Country.ISOCode)
	assert.Equal(t, "Linköping", record.City.Names.En)
	assert.Equal(t, "EU", record.Continent.Code)

	_, err = geo.Lookup("589.160.20.128")
	assert.Error(t, err)
}
