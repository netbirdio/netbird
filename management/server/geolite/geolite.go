package geolite

import (
	"fmt"
	"net"
	"os"

	"github.com/oschwald/maxminddb-golang"
)

type GeoLite struct {
	db *maxminddb.Reader
}

type Record struct {
	City struct {
		Names struct {
			En string `maxminddb:"en"`
		} `maxminddb:"names"`
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"city"`
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

func NewGeoLite(path string) (*GeoLite, error) {
	_, err := os.Stat(path)

	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%v does not exist", path)
	} else if err != nil {
		return nil, err
	}

	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%v could not be opened: %w", path, err)
	}

	return &GeoLite{db: db}, nil
}

func (gl GeoLite) Lookup(ip string) (*Record, error) {
	parsedIp := net.ParseIP(ip)
	if parsedIp == nil {
		return nil, fmt.Errorf("could not parse IP %s", ip)
	}

	var record Record
	err := gl.db.Lookup(parsedIp, &record)
	if err != nil {
		return nil, err
	}

	return &record, nil
}
