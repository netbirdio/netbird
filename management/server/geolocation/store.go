package geolocation

import (
	"fmt"
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
	file := filepath.Join(dataDir, "geonames.db")
	_, err := fileExists(file)
	if err != nil {
		return nil, err
	}

	storeStr := ":memory:?cache=shared&mode=ro"
	if runtime.GOOS == "windows" {
		storeStr = ":memory:?&mode=ro"
	}

	db, err := gorm.Open(sqlite.Open(storeStr), &gorm.Config{
		Logger:      logger.Default.LogMode(logger.Silent),
		PrepareStmt: true,
	})
	if err != nil {
		return nil, err
	}

	if err := setupInMemoryDBFromFile(db, file); err != nil {
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
func (s *SqliteStore) GetAllCountries() ([]Country, error) {
	var countries []Country
	result := s.db.Table("geonames").
		Select("country_iso_code", "country_name").
		Group("country_name").
		Scan(&countries)
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

// setupInMemoryDBFromFile prepares an in-memory DB by attaching a file database and,
// copies the data from the attached database to the in-memory database.
func setupInMemoryDBFromFile(db *gorm.DB, source string) error {
	// Attach the on-disk database to the in-memory database
	attachStmt := fmt.Sprintf("ATTACH DATABASE '%s' AS source;", source)
	if err := db.Exec(attachStmt).Error; err != nil {
		return err
	}

	err := db.Exec(`
		CREATE TABLE geonames AS SELECT * FROM source.geonames;
	`).Error
	if err != nil {
		return err
	}

	// Detach the on-disk database from the in-memory database
	err = db.Exec("DETACH DATABASE source;").Error
	if err != nil {
		return err
	}

	return nil
}
