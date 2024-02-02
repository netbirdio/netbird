package geolocation

import (
	"path/filepath"
	"runtime"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// SqliteStore represents a location storage backed by a Sqlite DB.
type SqliteStore struct {
	db *gorm.DB
}

func NewSqliteStore(dataDir string) (*SqliteStore, error) {
	storeStr := "geonames.db?cache=shared&mode=ro"
	if runtime.GOOS == "windows" {
		storeStr = "geonames.db?&mode=ro"
	}

	_, err := fileExists(filepath.Join(dataDir, "geonames.db"))
	if err != nil {
		return nil, err
	}

	file := filepath.Join(dataDir, storeStr)
	db, err := gorm.Open(sqlite.Open(file), &gorm.Config{
		Logger:      logger.Default.LogMode(logger.Silent),
		PrepareStmt: true,
	})
	if err != nil {
		return nil, err
	}

	sql, err := db.DB()
	if err != nil {
		return nil, err
	}
	conns := runtime.NumCPU()
	sql.SetMaxOpenConns(conns)

	return &SqliteStore{db: db}, nil
}

// GetAllCountries returns a list of all countries in the store.
func (s *SqliteStore) GetAllCountries() ([]string, error) {
	var countries []string
	result := s.db.Table("geonames").Distinct("country_iso_code").Pluck("country_iso_code", &countries)
	if result.Error != nil {
		return nil, result.Error
	}
	return countries, nil
}

// GetCitiesByCountry retrieves a list of cities from the store based on the given country ISO code.
func (s *SqliteStore) GetCitiesByCountry(countryISOCode string) ([]City, error) {
	var cities []City
	result := s.db.Table("geonames").
		Select("geoname_id", "city_name").
		Where("country_iso_code = ?", countryISOCode).
		Group("city_name").
		Scan(&cities)
	if result.Error != nil {
		return nil, result.Error
	}

	return cities, nil
}
