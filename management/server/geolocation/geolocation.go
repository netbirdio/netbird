package geolocation

import (
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
	log "github.com/sirupsen/logrus"
)

type Geolocation interface {
	Lookup(ip net.IP) (*Record, error)
	GetAllCountries() ([]Country, error)
	GetCitiesByCountry(countryISOCode string) ([]City, error)
	Stop() error
}

type geolocationImpl struct {
	mmdbPath   string
	mux        sync.RWMutex
	db         *maxminddb.Reader
	locationDB *SqliteStore
	stopCh     chan struct{}
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

const (
	mmdbPattern       = "GeoLite2-City_*.mmdb"
	geonamesdbPattern = "geonames_*.db"
)

func NewGeolocation(ctx context.Context, dataDir string, autoUpdate bool) (Geolocation, error) {
	mmdbFile, err := ensureDatabase(ctx, dataDir, mmdbPattern, geoLiteCityTarGZURL, autoUpdate, downloadMMDB)
	if err != nil {
		return nil, fmt.Errorf("prepare MaxMind database: %w", err)
	}

	geonamesDbFile, err := ensureDatabase(ctx, dataDir, geonamesdbPattern, geoLiteCityZipURL, autoUpdate, downloadGeonamesDB)
	if err != nil {
		return nil, fmt.Errorf("prepare geonames database: %w", err)
	}

	mmdbPath := path.Join(dataDir, mmdbFile)
	db, err := openDB(mmdbPath)
	if err != nil {
		return nil, err
	}

	locationDB, err := NewSqliteStore(ctx, dataDir, geonamesDbFile)
	if err != nil {
		return nil, err
	}

	geo := &geolocationImpl{
		mmdbPath:   mmdbPath,
		mux:        sync.RWMutex{},
		db:         db,
		locationDB: locationDB,
		stopCh:     make(chan struct{}),
	}

	return geo, nil
}

// downloadFunc fetches a database and stores it as filename in dataDir.
type downloadFunc func(ctx context.Context, dataDir, filename string) error

// ensureDatabase returns a usable database file matching pattern in dataDir. When the update
// fails it falls back to the newest file on disk, so old files are removed only after the
// wanted one is in place.
func ensureDatabase(ctx context.Context, dataDir, pattern, url string, autoUpdate bool, download downloadFunc) (string, error) {
	globPattern := filepath.Join(dataDir, pattern)

	filename, err := getDatabaseFilename(ctx, url, globPattern, autoUpdate)
	if err == nil {
		err = ensureFile(ctx, dataDir, filename, download)
	}
	if err == nil {
		if cleanupErr := cleanupOldDatabases(ctx, globPattern, filename); cleanupErr != nil {
			log.WithContext(ctx).Warnf("Failed to remove old databases: %v", cleanupErr)
		}
		return filename, nil
	}

	existing := getExistingDatabases(globPattern)
	if len(existing) == 0 {
		return "", err
	}
	fallback := filepath.Base(existing[len(existing)-1])
	log.WithContext(ctx).Warnf("Could not update geolocation database, using existing %s: %v", fallback, err)
	return fallback, nil
}

// ensureFile downloads filename into dataDir unless it exists. A failed download removes
// what it left behind, so a partial file is never picked up as a database.
func ensureFile(ctx context.Context, dataDir, filename string, download downloadFunc) error {
	target := path.Join(dataDir, filename)
	if exists, _ := fileExists(target); exists {
		return nil
	}

	log.WithContext(ctx).Infof("Geolocation database file %s not found, file will be downloaded", filename)
	if err := download(ctx, dataDir, filename); err != nil {
		if removeErr := os.Remove(target); removeErr != nil && !os.IsNotExist(removeErr) {
			log.WithContext(ctx).Warnf("Failed to remove incomplete database %s: %v", target, removeErr)
		}
		return fmt.Errorf("download %s: %w", filename, err)
	}
	return nil
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

func (gl *geolocationImpl) Stop() error {
	close(gl.stopCh)

	gl.mux.Lock()
	db := gl.db
	gl.db = nil
	gl.mux.Unlock()

	if db != nil {
		if err := db.Close(); err != nil {
			return err
		}
	}
	if gl.locationDB != nil {
		if err := gl.locationDB.close(); err != nil {
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

func getDatabaseFilename(ctx context.Context, databaseURL string, filenamePattern string, autoUpdate bool) (string, error) {
	var (
		filename string
		err      error
	)

	if autoUpdate {
		filename, err = getFilenameFromURL(ctx, databaseURL)
		if err != nil {
			log.WithContext(ctx).Debugf("Failed to update database from url: %s", databaseURL)
			return "", err
		}
	} else {
		files := getExistingDatabases(filenamePattern)
		if len(files) < 1 {
			filename, err = getFilenameFromURL(ctx, databaseURL)
			if err != nil {
				log.WithContext(ctx).Debugf("Failed to get database from url: %s", databaseURL)
				return "", err
			}
		} else {
			filename = filepath.Base(files[len(files)-1])
			log.WithContext(ctx).Debugf("Using existing database, %s", filename)
			return filename, nil
		}
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
	databaseFilename := filepath.Base(strings.Replace(filenamePattern, "*", date, 1))

	return databaseFilename, nil
}

func cleanupOldDatabases(ctx context.Context, pattern string, currentFile string) error {
	files := getExistingDatabases(pattern)

	for _, db := range files {
		if filepath.Base(db) == currentFile {
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

func (g *Mock) Stop() error {
	return nil
}
