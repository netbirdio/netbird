package geolocation

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
	log "github.com/sirupsen/logrus"
)

type Geolocation struct {
	mmdbPath            string
	mux                 sync.RWMutex
	sha256sum           []byte
	db                  *maxminddb.Reader
	locationDB          *SqliteStore
	stopCh              chan struct{}
	reloadCheckInterval time.Duration
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

var (
	mmdbPattern       = "GeoLite2-City_*"
	geonamesdbPattern = "GeoLite2-City-geonames_*"
)

func NewGeolocation(ctx context.Context, dataDir string, mmdbFile string, geonamesdbFile string) (*Geolocation, error) {
	var err error

	mmdbPattern = path.Join(dataDir, mmdbPattern)
	geonamesdbPattern = path.Join(dataDir, geonamesdbPattern)

	if mmdbFile == "" {
		mmdbFile, err = getMMDBFilename()
		if err != nil {
			return nil, fmt.Errorf("failed to get mmdb filename: %v", err)
		}
	}

	if geonamesdbFile == "" {
		geonamesdbFile, err = getGeoNamesDBFilename()
		if err != nil {
			return nil, fmt.Errorf("failed to get geonames db filename: %v", err)
		}
	}

	if err := loadGeolocationDatabases(dataDir, mmdbFile, geonamesdbFile); err != nil {
		return nil, fmt.Errorf("failed to load MaxMind databases: %v", err)
	}

	if err := cleanupOldDatabases(mmdbPattern, mmdbFile); err != nil {
		return nil, fmt.Errorf("failed to remove old mmdb: %v", err)
	}
	if err := cleanupOldDatabases(geonamesdbPattern, geonamesdbFile); err != nil {
		return nil, fmt.Errorf("failed to remove old geonames db: %v", err)
	}

	mmdbPath := path.Join(dataDir, mmdbFile)
	db, err := openDB(mmdbPath)
	if err != nil {
		return nil, err
	}

	sha256sum, err := calculateFileSHA256(mmdbPath)
	if err != nil {
		return nil, err
	}

	locationDB, err := NewSqliteStore(ctx, dataDir, geonamesdbFile)
	if err != nil {
		return nil, err
	}

	geo := &Geolocation{
		mmdbPath:            mmdbPath,
		mux:                 sync.RWMutex{},
		sha256sum:           sha256sum,
		db:                  db,
		locationDB:          locationDB,
		reloadCheckInterval: 300 * time.Second, // TODO: make configurable
		stopCh:              make(chan struct{}),
	}

	go geo.reloader(ctx)

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

func (gl *Geolocation) reloader(ctx context.Context) {
	for {
		select {
		case <-gl.stopCh:
			return
		case <-time.After(gl.reloadCheckInterval):
			if err := gl.locationDB.reload(ctx); err != nil {
				log.WithContext(ctx).Errorf("geonames db reload failed: %s", err)
			}

			newSha256sum1, err := calculateFileSHA256(gl.mmdbPath)
			if err != nil {
				log.WithContext(ctx).Errorf("failed to calculate sha256 sum for '%s': %s", gl.mmdbPath, err)
				continue
			}
			if !bytes.Equal(gl.sha256sum, newSha256sum1) {
				// we check sum twice just to avoid possible case when we reload during update of the file
				// considering the frequency of file update (few times a week) checking sum twice should be enough
				time.Sleep(50 * time.Millisecond)
				newSha256sum2, err := calculateFileSHA256(gl.mmdbPath)
				if err != nil {
					log.WithContext(ctx).Errorf("failed to calculate sha256 sum for '%s': %s", gl.mmdbPath, err)
					continue
				}
				if !bytes.Equal(newSha256sum1, newSha256sum2) {
					log.WithContext(ctx).Errorf("sha256 sum changed during reloading of '%s'", gl.mmdbPath)
					continue
				}
				err = gl.reload(ctx, newSha256sum2)
				if err != nil {
					log.WithContext(ctx).Errorf("mmdb reload failed: %s", err)
				}
			} else {
				log.WithContext(ctx).Tracef("No changes in '%s', no need to reload. Next check is in %.0f seconds.",
					gl.mmdbPath, gl.reloadCheckInterval.Seconds())
			}
		}
	}
}

func (gl *Geolocation) reload(ctx context.Context, newSha256sum []byte) error {
	gl.mux.Lock()
	defer gl.mux.Unlock()

	log.WithContext(ctx).Infof("Reloading '%s'", gl.mmdbPath)

	err := gl.db.Close()
	if err != nil {
		return err
	}

	db, err := openDB(gl.mmdbPath)
	if err != nil {
		return err
	}

	gl.db = db
	gl.sha256sum = newSha256sum

	log.WithContext(ctx).Infof("Successfully reloaded '%s'", gl.mmdbPath)

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

func getMMDBFilename() (string, error) {
	filename, err := getFilenameFromURL(geoLiteCityTarGZURL)
	if err != nil {
		files := getExistingDatabases(mmdbPattern)
		if len(files) < 1 {
			return "", err
		}
		filename = path.Base(files[len(files)-1])
		log.Infof("Failed to get mmdb filename. Falling back to existing database: %s", filename)
		return filename, nil
	}

	basename := strings.TrimSuffix(filename, ".tar.gz")
	mmdbFilename := path.Base(basename) + ".mmdb"
	return mmdbFilename, nil
}

func getGeoNamesDBFilename() (string, error) {
	filename, err := getFilenameFromURL(geoLiteCityZipURL)
	if err != nil {
		files := getExistingDatabases(geonamesdbPattern)
		if len(files) < 1 {
			return "", err
		}
		filename = path.Base(files[len(files)-1])
		log.Infof("Failed to get geonames db filename. Falling back to existing database: %s", filename)
		return filename, nil
	}

	basename := strings.TrimSuffix(filename, ".zip")
	geonamesdbFilename := strings.Replace(path.Base(basename), "CSV", "geonames", 1) + ".db"
	return geonamesdbFilename, nil
}

func getExistingDatabases(pattern string) []string {
	files, _ := filepath.Glob(pattern)
	return files
}

func cleanupOldDatabases(pattern string, currentFile string) error {
	files := getExistingDatabases(pattern)

	for _, f := range files {
		if path.Base(f) == currentFile {
			continue
		}
		log.Infof("Removing old database: %s", f)
		err := os.Remove(f)
		if err != nil {
			return err
		}
	}
	return nil
}
