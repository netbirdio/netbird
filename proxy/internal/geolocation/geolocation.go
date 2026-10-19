// Package geolocation provides IP-to-country lookups using MaxMind GeoLite2 databases.
package geolocation

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/oschwald/maxminddb-golang"
	log "github.com/sirupsen/logrus"
)

const (
	// EnvDisable disables geolocation lookups entirely when set to a truthy value.
	EnvDisable = "NB_PROXY_DISABLE_GEOLOCATION"

	// DefaultUpdateInterval is how often the remote database version is checked.
	DefaultUpdateInterval = 24 * time.Hour
	// MinUpdateInterval is the lowest accepted update check interval.
	MinUpdateInterval = time.Hour

	mmdbGlob   = "GeoLite2-City_*.mmdb"
	maxBackoff = 30 * time.Minute
)

var initialBackoff = 10 * time.Second

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
	path   string
	logger *log.Logger

	dataDir        string
	updateInterval time.Duration
	client         *http.Client
	cancel         context.CancelFunc
	done           chan struct{}
}

// NewLookup loads the newest GeoLite2-City MMDB in dataDir and keeps it
// current in the background. It never blocks on the network: without a usable
// local file the database is downloaded in a background goroutine and
// Available reports false until it is loaded (country restrictions deny all
// requests meanwhile). Every updateInterval the remote version is checked and
// a newer database is swapped in. Returns nil without error if geolocation is
// disabled via environment variable or no data directory is configured.
func NewLookup(logger *log.Logger, dataDir string, updateInterval time.Duration) (*Lookup, error) {
	if isDisabledByEnv(logger) {
		logger.Info("geolocation disabled via environment variable")
		return nil, nil //nolint:nilnil
	}

	if dataDir == "" {
		return nil, nil //nolint:nilnil
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create geo data directory %s: %w", dataDir, err)
	}

	switch {
	case updateInterval <= 0:
		updateInterval = DefaultUpdateInterval
	case updateInterval < MinUpdateInterval:
		logger.Warnf("geolocation update interval %s is below the minimum, using %s", updateInterval, MinUpdateInterval)
		updateInterval = MinUpdateInterval
	}

	ctx, cancel := context.WithCancel(context.Background())
	l := &Lookup{
		logger:         logger,
		dataDir:        dataDir,
		updateInterval: updateInterval,
		client:         &http.Client{Timeout: downloadTimeout},
		cancel:         cancel,
		done:           make(chan struct{}),
	}
	l.loadLocal()
	if !l.Available() {
		logger.Warn("geolocation database not loaded, country-based access restrictions will deny all requests until it is downloaded")
	}

	go l.run(ctx)
	return l, nil
}

// loadLocal opens the newest valid database in dataDir and removes files that
// fail to open.
func (l *Lookup) loadLocal() {
	files, _ := filepath.Glob(filepath.Join(l.dataDir, mmdbGlob))
	sort.Strings(files)
	for i := len(files) - 1; i >= 0; i-- {
		db, err := maxminddb.Open(files[i])
		if err != nil {
			l.logger.Warnf("open geolocation database %s, removing: %v", files[i], err)
			if err := os.Remove(files[i]); err != nil && !errors.Is(err, os.ErrNotExist) {
				l.logger.Warnf("remove corrupt geolocation database %s: %v", files[i], err)
			}
			continue
		}
		l.db = db
		l.path = files[i]
		l.logger.Infof("geolocation database loaded from %s", files[i])
		return
	}
}

func (l *Lookup) run(ctx context.Context) {
	defer close(l.done)

	if !l.Available() {
		b := backoff.NewExponentialBackOff()
		b.InitialInterval = initialBackoff
		b.MaxInterval = maxBackoff
		b.MaxElapsedTime = 0
		b.Reset()
		err := backoff.RetryNotify(
			func() error { return l.update(ctx) },
			backoff.WithContext(b, ctx),
			func(err error, next time.Duration) {
				l.logger.Warnf("download geolocation database, retrying in %s: %v", next, err)
			},
		)
		if err != nil {
			return
		}
	} else if err := l.update(ctx); err != nil && ctx.Err() == nil {
		l.logger.Warnf("check for geolocation database update: %v", err)
	}

	ticker := time.NewTicker(l.updateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := l.update(ctx); err != nil && ctx.Err() == nil {
				l.logger.Warnf("check for geolocation database update: %v", err)
			}
		}
	}
}

// update loads the remote database if its filename differs from the loaded
// one, then removes older databases from the data directory.
func (l *Lookup) update(ctx context.Context) error {
	datedName, err := fetchRemoteFilename(ctx, l.client, mmdbTarGZURL)
	if err != nil {
		return fmt.Errorf("get remote filename: %w", err)
	}

	l.mu.RLock()
	current := l.path
	l.mu.RUnlock()

	newPath := filepath.Join(l.dataDir, deriveMMDBFilename(datedName))
	if current != "" && filepath.Base(newPath) <= filepath.Base(current) {
		return nil
	}

	db, err := maxminddb.Open(newPath)
	if err != nil {
		if newPath, err = downloadMMDB(ctx, l.logger, l.client, l.dataDir, datedName); err != nil {
			return err
		}
		if db, err = maxminddb.Open(newPath); err != nil {
			return fmt.Errorf("open GeoLite2 database %s: %w", newPath, err)
		}
	}

	l.mu.Lock()
	old := l.db
	l.db = db
	l.path = newPath
	l.mu.Unlock()

	if old != nil {
		if err := old.Close(); err != nil {
			l.logger.Warnf("close previous geolocation database: %v", err)
		}
	}
	l.logger.Infof("geolocation database loaded from %s", newPath)
	l.removeOlder(newPath)
	return nil
}

// removeOlder deletes databases in dataDir whose name sorts lower than keep.
// Newer files may belong to another instance sharing the directory.
func (l *Lookup) removeOlder(keep string) {
	files, _ := filepath.Glob(filepath.Join(l.dataDir, mmdbGlob))
	for _, f := range files {
		if filepath.Base(f) >= filepath.Base(keep) {
			continue
		}
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			l.logger.Warnf("remove old geolocation database %s: %v", f, err)
		}
	}
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

// Close stops the background updater and releases the database resources.
func (l *Lookup) Close() error {
	if l == nil {
		return nil
	}
	l.cancel()
	<-l.done
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
