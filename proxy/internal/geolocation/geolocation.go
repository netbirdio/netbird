// Package geolocation provides IP-to-country lookups using MaxMind GeoLite2 databases.
package geolocation

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"sync"

	"github.com/oschwald/maxminddb-golang"
	log "github.com/sirupsen/logrus"
)

const (
	// EnvDisable disables geolocation lookups entirely when set to a truthy value.
	EnvDisable = "NB_PROXY_DISABLE_GEOLOCATION"
	// EnvDataDir overrides the directory where the GeoLite2 MMDB file is stored.
	EnvDataDir = "NB_PROXY_GEOLOCATION_DATA_DIR"

	mmdbGlob = "GeoLite2-City_*.mmdb"
)

type record struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names struct {
			En string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		ISOCode string `maxminddb:"iso_code"`
		Names   struct {
			En string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

// Result holds the outcome of a geo lookup.
type Result struct {
	CountryCode     string
	CityName        string
	SubdivisionCode string
	SubdivisionName string
}

// Lookup provides IP geolocation lookups.
type Lookup struct {
	mu     sync.RWMutex
	db     *maxminddb.Reader
	logger *log.Logger
}

// NewLookup opens or downloads the GeoLite2-City MMDB in dataDir.
// Returns nil without error if geolocation is disabled via environment
// variable, no data directory is configured, or the download fails
// (graceful degradation: country restrictions will deny all requests).
func NewLookup(logger *log.Logger, dataDir string) (*Lookup, error) {
	if isDisabledByEnv(logger) {
		logger.Info("geolocation disabled via environment variable")
		return nil, nil
	}

	if envDir := os.Getenv(EnvDataDir); envDir != "" {
		dataDir = envDir
	}

	if dataDir == "" {
		return nil, nil
	}

	mmdbPath, err := ensureMMDB(logger, dataDir)
	if err != nil {
		logger.Warnf("geolocation database unavailable: %v", err)
		logger.Warn("country-based access restrictions will deny all requests until a database is available")
		return nil, nil
	}

	db, err := maxminddb.Open(mmdbPath)
	if err != nil {
		return nil, fmt.Errorf("open GeoLite2 database %s: %w", mmdbPath, err)
	}

	logger.Infof("geolocation database loaded from %s", mmdbPath)
	return &Lookup{db: db, logger: logger}, nil
}

// LookupAddr returns the country ISO code and city name for the given IP.
// Returns an empty Result if the database is nil or the lookup fails.
func (l *Lookup) LookupAddr(addr netip.Addr) Result {
	if l == nil {
		return Result{}
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.db == nil {
		return Result{}
	}

	addr = addr.Unmap()

	var rec record
	if err := l.db.Lookup(addr.AsSlice(), &rec); err != nil {
		l.logger.Debugf("geolocation lookup %s: %v", addr, err)
		return Result{}
	}
	r := Result{
		CountryCode: rec.Country.ISOCode,
		CityName:    rec.City.Names.En,
	}
	if len(rec.Subdivisions) > 0 {
		r.SubdivisionCode = rec.Subdivisions[0].ISOCode
		r.SubdivisionName = rec.Subdivisions[0].Names.En
	}
	return r
}

// Available reports whether the lookup has a loaded database.
func (l *Lookup) Available() bool {
	if l == nil {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.db != nil
}

// Close releases the database resources.
func (l *Lookup) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.db != nil {
		err := l.db.Close()
		l.db = nil
		return err
	}
	return nil
}

func isDisabledByEnv(logger *log.Logger) bool {
	val := os.Getenv(EnvDisable)
	if val == "" {
		return false
	}
	disabled, err := strconv.ParseBool(val)
	if err != nil {
		logger.Warnf("parse %s=%q: %v", EnvDisable, val, err)
		return false
	}
	return disabled
}
