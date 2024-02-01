package geolocation

import (
	"path/filepath"
	"runtime"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// SqliteStore represents an account storage backed by a Sqlite DB persisted to disk
type SqliteStore struct {
	db        *gorm.DB
	storeFile string
}

func NewSqliteStore(dataDir string) (*SqliteStore, error) {
	storeStr := "geonames.db?cache=shared"
	if runtime.GOOS == "windows" {
		// Vo avoid `The process cannot access the file because it is being used by another process` on Windows
		storeStr = "geonames.db"
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
	sql.SetMaxOpenConns(conns) // TODO: make it configurable

	return &SqliteStore{db: db, storeFile: file}, nil
}

func (s *SqliteStore) GetAllCountries() ([]string, error) {
	var countries []string
	result := s.db.Table("geonames").Distinct("country_iso_code").Pluck("country_iso_code", &countries)
	if result.Error != nil {
		return nil, result.Error
	}
	return countries, nil
}

func (s *SqliteStore) GetCitiesByCountry(countryISOCode string) ([]string, error) {
	var cities []string
	result := s.db.Table("geonames").
		Where("country_iso_code = ?", countryISOCode).
		Distinct("city_name").
		Pluck("city_name", &cities)
	if result.Error != nil {
		return nil, result.Error
	}
	return cities, nil
}
