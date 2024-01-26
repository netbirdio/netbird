package geolocation

import (
	"fmt"
	"net"
	"os"
	"path"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

type Geolocation struct {
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

func NewGeolocation(datadir string) (*Geolocation, error) {
	mmdbPath := path.Join(datadir, "GeoLite2-City.mmdb")

	db, err := openDB(mmdbPath)
	if err != nil {
		return nil, err
	}
	return &Geolocation{
		path: mmdbPath,
		mux:  &sync.RWMutex{},
		db:   db,
	}, nil
}

func openDB(mmdbPath string) (*maxminddb.Reader, error) {
	_, err := os.Stat(mmdbPath)

	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%v does not exist", mmdbPath)
	} else if err != nil {
		return nil, err
	}

	db, err := maxminddb.Open(mmdbPath)
	if err != nil {
		return nil, fmt.Errorf("%v could not be opened: %w", mmdbPath, err)
	}

	return db, nil
}

func (gl *Geolocation) Lookup(ip string) (*Record, error) {
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

func (gl *Geolocation) Reload() error {
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
