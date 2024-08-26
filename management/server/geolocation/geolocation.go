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

type Geolocation struct {
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

func NewGeolocation(ctx context.Context, dataDir string, autoUpdate bool) (*Geolocation, error) {
	mmdbGlobPattern := filepath.Join(dataDir, mmdbPattern)
	mmdbFile, err := getDatabaseFilename(ctx, geoLiteCityTarGZURL, mmdbGlobPattern, autoUpdate)
	if err != nil {
		return nil, fmt.Errorf("failed to get database filename: %v", err)
	}

	geonamesDbGlobPattern := filepath.Join(dataDir, geonamesdbPattern)
	geonamesDbFile, err := getDatabaseFilename(ctx, geoLiteCityZipURL, geonamesDbGlobPattern, autoUpdate)
	if err != nil {
		return nil, fmt.Errorf("failed to get database filename: %v", err)
	}

	if err := loadGeolocationDatabases(ctx, dataDir, mmdbFile, geonamesDbFile); err != nil {
		return nil, fmt.Errorf("failed to load MaxMind databases: %v", err)
	}

	if err := cleanupMaxMindDatabases(ctx, dataDir, mmdbFile, geonamesDbFile); err != nil {
		return nil, fmt.Errorf("failed to remove old MaxMind databases: %v", err)
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

	geo := &Geolocation{
		mmdbPath:   mmdbPath,
		mux:        sync.RWMutex{},
		db:         db,
		locationDB: locationDB,
		stopCh:     make(chan struct{}),
	}

	return geo, nil
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

func (gl *Geolocation) Lookup(ip net.IP) (*Record, error) {
	gl.mux.RLock()
	defer gl.mux.RUnlock()

	var record Record
	err := gl.db.Lookup(ip, &record)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// GetAllCountries retrieves a list of all countries.
func (gl *Geolocation) GetAllCountries() ([]Country, error) {
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
func (gl *Geolocation) GetCitiesByCountry(countryISOCode string) ([]City, error) {
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

func (gl *Geolocation) Stop() error {
	close(gl.stopCh)
	if gl.db != nil {
		if err := gl.db.Close(); err != nil {
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
		filename, err = getFilenameFromURL(databaseURL)
		if err != nil {
			log.WithContext(ctx).Debugf("Failed to update database from url: %s", databaseURL)
			return "", err
		}
	} else {
		files := getExistingDatabases(filenamePattern)
		if len(files) < 1 {
			filename, err = getFilenameFromURL(databaseURL)
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
	date := strings.SplitN(basename, "_", 2)[1]
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
