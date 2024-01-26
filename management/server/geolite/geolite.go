package geolite

import (
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

type GeoLite struct {
	path string
	mux  *sync.RWMutex
	db   *maxminddb.Reader
}

type Record struct {
	City struct {
		GeonameID uint `maxminddb:"geoname_id"`
		Names     struct {
			En string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"city"`
	Continent struct {
		GeonameID uint   `maxminddb:"geoname_id"`
		Code      string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Country struct {
		GeonameID uint   `maxminddb:"geoname_id"`
		ISOCode   string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

func NewGeoLite(path string) (*GeoLite, error) {
	db, err := openDB(path)
	if err != nil {
		return nil, err
	}
	return &GeoLite{
		path: path,
		mux:  &sync.RWMutex{},
		db:   db,
	}, nil
}

func openDB(path string) (*maxminddb.Reader, error) {
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

	return db, nil
}

func (gl *GeoLite) Lookup(ip string) (*Record, error) {
	gl.mux.RLock()
	defer gl.mux.RUnlock()

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

func (gl *GeoLite) Reload() error {
	gl.mux.Lock()
	defer gl.mux.Unlock()

	err := gl.db.Close()
	if err != nil {
		return err
	}

	db, err := openDB(gl.path)
	if err != nil {
		return err
	}

	gl.db = db

	return nil
}
