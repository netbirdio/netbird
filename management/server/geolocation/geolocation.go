package geolocation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/oschwald/maxminddb-golang"
	log "github.com/sirupsen/logrus"
)

type Geolocation interface {
	Lookup(ip net.IP) (*Record, error)
	GetAllCountries() ([]Country, error)
	GetCitiesByCountry(countryISOCode string) ([]City, error)
	// WaitReady blocks until a database is loaded, ctx is done or the service is stopped.
	WaitReady(ctx context.Context) error
	Stop() error
}

type geolocationImpl struct {
	dataDir        string
	mux            sync.RWMutex
	db             *maxminddb.Reader
	locationDB     *SqliteStore
	mmdbFile       string
	geonamesDbFile string
	ready          chan struct{}
	readyOnce      sync.Once
	done           <-chan struct{}
	cancel         context.CancelFunc
	wg             sync.WaitGroup
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
	Subdivisions []struct {
		ISOCode string `maxminddb:"iso_code"`
		Names   struct {
			En string `maxminddb:"en"`
		} `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

type City struct {
	GeoNameID int `gorm:"column:geoname_id"`
	CityName  string
}

type Country struct {
	CountryISOCode string `gorm:"column:country_iso_code"`
	CountryName    string
}

// ErrStopped is returned by WaitReady when the service is stopped before a database has been loaded.
var ErrStopped = errors.New("geolocation service stopped")

// DefaultUpdateInterval is the interval between update checks used when NewGeolocation gets a non-positive one.
const DefaultUpdateInterval = 24 * time.Hour

// MinUpdateInterval is the shortest interval between update checks; shorter ones are raised to it.
const MinUpdateInterval = time.Hour

const (
	mmdbPattern       = "GeoLite2-City_*.mmdb"
	geonamesdbPattern = "geonames_*.db"
)

// NewGeolocation opens the newest geolocation databases found in dataDir and returns without blocking on the network.
// Missing databases are downloaded in the background; WaitReady reports when a database has been loaded. When
// autoUpdate is set, newer databases are downloaded at startup and every updateInterval, and swapped in while running.
func NewGeolocation(ctx context.Context, dataDir string, autoUpdate bool, updateInterval time.Duration) Geolocation {
	ctx, cancel := context.WithCancel(ctx)
	gl := &geolocationImpl{
		dataDir: dataDir,
		ready:   make(chan struct{}),
		done:    ctx.Done(),
		cancel:  cancel,
	}

	mmdbFile := latestDatabase(filepath.Join(dataDir, mmdbPattern))
	geonamesDbFile := latestDatabase(filepath.Join(dataDir, geonamesdbPattern))
	loaded := false
	if mmdbFile != "" && geonamesDbFile != "" {
		if failedFile, err := gl.open(ctx, mmdbFile, geonamesDbFile); err != nil {
			log.WithContext(ctx).Warnf("failed to open local geolocation databases, downloading them: %v", err)
			_ = os.Remove(path.Join(dataDir, failedFile))
		} else {
			loaded = true
			if err := cleanupMaxMindDatabases(ctx, dataDir, mmdbFile, geonamesDbFile); err != nil {
				log.WithContext(ctx).Warnf("failed to remove old MaxMind databases: %v", err)
			}
		}
	}

	if !loaded {
		log.WithContext(ctx).Warnf("no usable geolocation databases in %s, startup waits until they are downloaded", dataDir)
	}

	switch {
	case updateInterval <= 0:
		updateInterval = DefaultUpdateInterval
	case updateInterval < MinUpdateInterval:
		log.WithContext(ctx).Warnf("geolocation update interval %s is below the minimum, using %s", updateInterval, MinUpdateInterval)
		updateInterval = MinUpdateInterval
	}

	if !loaded || autoUpdate {
		gl.wg.Go(func() {
			gl.run(ctx, loaded, autoUpdate, updateInterval)
		})
	}

	return gl
}

// run downloads the databases until one is loaded when none is, then checks for newer ones every updateInterval when autoUpdate is set.
func (gl *geolocationImpl) run(ctx context.Context, loaded, autoUpdate bool, updateInterval time.Duration) {
	if !loaded {
		gl.updateWithRetry(ctx)
	} else if autoUpdate {
		gl.tryUpdate(ctx)
	}

	if !autoUpdate {
		return
	}

	ticker := time.NewTicker(updateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			gl.tryUpdate(ctx)
		}
	}
}

func (gl *geolocationImpl) tryUpdate(ctx context.Context) {
	if err := gl.update(ctx); err != nil && ctx.Err() == nil {
		log.WithContext(ctx).Warnf("failed to update geolocation databases: %v", err)
	}
}

// updateWithRetry downloads the latest databases and swaps them in, retrying with backoff until it succeeds or ctx is done.
func (gl *geolocationImpl) updateWithRetry(ctx context.Context) {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 10 * time.Second
	b.MaxInterval = 30 * time.Minute
	b.MaxElapsedTime = 0

	_ = backoff.RetryNotify(func() error {
		return gl.update(ctx)
	}, backoff.WithContext(b, ctx), func(err error, next time.Duration) {
		log.WithContext(ctx).Warnf("failed to update geolocation databases, retrying in %s: %v", next, err)
	})
}

func (gl *geolocationImpl) update(ctx context.Context) error {
	gl.mux.RLock()
	currentMmdbFile, currentGeonamesDbFile := gl.mmdbFile, gl.geonamesDbFile
	gl.mux.RUnlock()

	mmdbFile, err := getDatabaseFilename(ctx, geoLiteCityTarGZURL, mmdbPattern)
	if err != nil {
		return fmt.Errorf("get database filename: %w", err)
	}

	geonamesDbFile, err := getDatabaseFilename(ctx, geoLiteCityZipURL, geonamesdbPattern)
	if err != nil {
		return fmt.Errorf("get database filename: %w", err)
	}

	if mmdbFile <= currentMmdbFile && geonamesDbFile <= currentGeonamesDbFile {
		log.WithContext(ctx).Debugf("geolocation databases %s and %s are up to date", currentMmdbFile, currentGeonamesDbFile)
		return nil
	}

	if err := loadGeolocationDatabases(ctx, gl.dataDir, mmdbFile, geonamesDbFile); err != nil {
		return fmt.Errorf("load MaxMind databases: %w", err)
	}

	if failedFile, err := gl.open(ctx, mmdbFile, geonamesDbFile); err != nil {
		if failedFile != currentMmdbFile && failedFile != currentGeonamesDbFile {
			_ = os.Remove(path.Join(gl.dataDir, failedFile))
		}
		return err
	}

	if err := cleanupMaxMindDatabases(ctx, gl.dataDir, mmdbFile, geonamesDbFile); err != nil {
		log.WithContext(ctx).Warnf("failed to remove old MaxMind databases: %v", err)
	}

	log.WithContext(ctx).Infof("geolocation databases %s and %s have been loaded", mmdbFile, geonamesDbFile)
	return nil
}

// open opens the given databases from the data directory and replaces the ones currently in use. On failure it
// returns the file that could not be opened.
func (gl *geolocationImpl) open(ctx context.Context, mmdbFile, geonamesDbFile string) (string, error) {
	db, err := openDB(path.Join(gl.dataDir, mmdbFile))
	if err != nil {
		return mmdbFile, err
	}

	locationDB, err := NewSqliteStore(ctx, gl.dataDir, geonamesDbFile)
	if err != nil {
		_ = db.Close()
		return geonamesDbFile, err
	}

	gl.mux.Lock()
	oldDB, oldLocationDB := gl.db, gl.locationDB
	gl.db, gl.locationDB = db, locationDB
	gl.mmdbFile, gl.geonamesDbFile = mmdbFile, geonamesDbFile
	gl.mux.Unlock()

	gl.readyOnce.Do(func() { close(gl.ready) })

	if oldDB != nil {
		_ = oldDB.Close()
	}
	if oldLocationDB != nil {
		_ = oldLocationDB.close()
	}
	return "", nil
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

func (gl *geolocationImpl) Lookup(ip net.IP) (*Record, error) {
	gl.mux.RLock()
	defer gl.mux.RUnlock()

	if gl.db == nil {
		return nil, fmt.Errorf("geolocation database is not available")
	}

	var record Record
	err := gl.db.Lookup(ip, &record)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// GetAllCountries retrieves a list of all countries.
func (gl *geolocationImpl) GetAllCountries() ([]Country, error) {
	gl.mux.RLock()
	defer gl.mux.RUnlock()

	if gl.locationDB == nil {
		return nil, errLocationDBNotLoaded
	}

	allCountries, err := gl.locationDB.GetAllCountries()
	if err != nil {
		return nil, err
	}

	countries := make([]Country, 0)
	for _, country := range allCountries {
		if country.CountryName != "" {
			countries = append(countries, country)
		}
	}
	return countries, nil
}

// GetCitiesByCountry retrieves a list of cities in a specific country based on the country's ISO code.
func (gl *geolocationImpl) GetCitiesByCountry(countryISOCode string) ([]City, error) {
	gl.mux.RLock()
	defer gl.mux.RUnlock()

	if gl.locationDB == nil {
		return nil, errLocationDBNotLoaded
	}

	allCities, err := gl.locationDB.GetCitiesByCountry(countryISOCode)
	if err != nil {
		return nil, err
	}

	cities := make([]City, 0)
	for _, city := range allCities {
		if city.CityName != "" {
			cities = append(cities, city)
		}
	}
	return cities, nil
}

// WaitReady blocks until a database is loaded, ctx is done or the service is stopped.
func (gl *geolocationImpl) WaitReady(ctx context.Context) error {
	select {
	case <-gl.ready:
		return nil
	default:
	}

	select {
	case <-gl.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-gl.done:
		return ErrStopped
	}
}

func (gl *geolocationImpl) Stop() error {
	gl.cancel()
	gl.wg.Wait()

	gl.mux.Lock()
	db, locationDB := gl.db, gl.locationDB
	gl.db, gl.locationDB = nil, nil
	gl.mux.Unlock()

	if db != nil {
		if err := db.Close(); err != nil {
			return err
		}
	}
	if locationDB != nil {
		if err := locationDB.close(); err != nil {
			return err
		}
	}
	return nil
}

func fileExists(filePath string) (bool, error) {
	_, err := os.Stat(filePath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, fmt.Errorf("%v does not exist", filePath)
	}
	return false, err
}

func getExistingDatabases(pattern string) []string {
	files, _ := filepath.Glob(pattern)
	return files
}

// latestDatabase returns the base name of the newest database matching pattern, or an empty string if there is none.
func latestDatabase(pattern string) string {
	files := getExistingDatabases(pattern)
	if len(files) == 0 {
		return ""
	}
	return filepath.Base(files[len(files)-1])
}

func getDatabaseFilename(ctx context.Context, databaseURL string, filenamePattern string) (string, error) {
	filename, err := getFilenameFromURL(ctx, databaseURL)
	if err != nil {
		log.WithContext(ctx).Debugf("Failed to get database from url: %s", databaseURL)
		return "", err
	}

	// strip suffixes that may be nested, such as .tar.gz
	basename := strings.SplitN(filename, ".", 2)[0]
	// get date version from basename
	parts := strings.SplitN(basename, "_", 2)
	if len(parts) < 2 || parts[1] == "" {
		return "", fmt.Errorf("unexpected database filename %q: missing date suffix", filename)
	}
	date := parts[1]
	// format db as "GeoLite2-Cities-{maxmind|geonames}_{DATE}.{mmdb|db}"
	databaseFilename := strings.Replace(filenamePattern, "*", date, 1)

	return databaseFilename, nil
}

func cleanupOldDatabases(ctx context.Context, pattern string, currentFile string) error {
	files := getExistingDatabases(pattern)

	for _, db := range files {
		// Instances sharing the data directory may already have stored a newer database.
		if filepath.Base(db) >= currentFile {
			continue
		}
		log.WithContext(ctx).Debugf("Removing old database: %s", db)
		err := os.Remove(db)
		if err != nil {
			return err
		}
	}
	return nil
}

func cleanupMaxMindDatabases(ctx context.Context, dataDir string, mmdbFile string, geonamesdbFile string) error {
	for _, file := range []string{mmdbFile, geonamesdbFile} {
		switch file {
		case mmdbFile:
			pattern := filepath.Join(dataDir, mmdbPattern)
			if err := cleanupOldDatabases(ctx, pattern, file); err != nil {
				return err
			}
		case geonamesdbFile:
			pattern := filepath.Join(dataDir, geonamesdbPattern)
			if err := cleanupOldDatabases(ctx, pattern, file); err != nil {
				return err
			}
		}
	}
	return nil
}

type Mock struct{}

func (g *Mock) Lookup(ip net.IP) (*Record, error) {
	return &Record{}, nil
}

func (g *Mock) GetAllCountries() ([]Country, error) {
	return []Country{}, nil
}

func (g *Mock) GetCitiesByCountry(countryISOCode string) ([]City, error) {
	return []City{}, nil
}

// WaitReady returns immediately because the mock needs no database.
func (g *Mock) WaitReady(context.Context) error {
	return nil
}

func (g *Mock) Stop() error {
	return nil
}
