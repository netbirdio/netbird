package geolocation

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/netbirdio/netbird/management/server/status"
)

type GeoNames struct {
	GeoNameID           int    `gorm:"column:geoname_id"`
	LocaleCode          string `gorm:"column:locale_code"`
	ContinentCode       string `gorm:"column:continent_code"`
	ContinentName       string `gorm:"column:continent_name"`
	CountryIsoCode      string `gorm:"column:country_iso_code"`
	CountryName         string `gorm:"column:country_name"`
	Subdivision1IsoCode string `gorm:"column:subdivision_1_iso_code"`
	Subdivision1Name    string `gorm:"column:subdivision_1_name"`
	Subdivision2IsoCode string `gorm:"column:subdivision_2_iso_code"`
	Subdivision2Name    string `gorm:"column:subdivision_2_name"`
	CityName            string `gorm:"column:city_name"`
	MetroCode           string `gorm:"column:metro_code"`
	TimeZone            string `gorm:"column:time_zone"`
	IsInEuropeanUnion   string `gorm:"column:is_in_european_union"`
}

func (*GeoNames) TableName() string {
	return "geonames"
}

// SqliteStore represents a location storage backed by a Sqlite DB.
type SqliteStore struct {
	db       *gorm.DB
	filePath string
	mux      sync.RWMutex
	closed   bool
}

func NewSqliteStore(ctx context.Context, dataDir string, dbPath string) (*SqliteStore, error) {
	file := filepath.Join(dataDir, dbPath)

	db, err := connectDB(ctx, file)
	if err != nil {
		return nil, err
	}

	return &SqliteStore{
		db:       db,
		filePath: file,
		mux:      sync.RWMutex{},
	}, nil
}

// GetAllCountries returns a list of all countries in the store.
func (s *SqliteStore) GetAllCountries() ([]Country, error) {
	s.mux.RLock()
	defer s.mux.RUnlock()

	if s.closed {
		return nil, status.Errorf(status.PreconditionFailed, "geo location database is not initialized")
	}

	var countries []Country
	result := s.db.Model(&GeoNames{}).
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
	s.mux.RLock()
	defer s.mux.RUnlock()

	if s.closed {
		return nil, status.Errorf(status.PreconditionFailed, "geo location database is not initialized")
	}

	var cities []City
	result := s.db.Model(&GeoNames{}).
		Select("geoname_id", "city_name").
		Where("country_iso_code = ?", countryISOCode).
		Group("city_name").
		Scan(&cities)
	if result.Error != nil {
		return nil, result.Error
	}

	return cities, nil
}

// close closes the database connection.
// It retrieves the underlying *sql.DB object from the *gorm.DB object
// and calls the Close() method on it.
func (s *SqliteStore) close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// connectDB connects to an SQLite database and prepares it by setting up an in-memory database.
func connectDB(ctx context.Context, filePath string) (*gorm.DB, error) {
	start := time.Now()
	defer func() {
		log.WithContext(ctx).Debugf("took %v to setup geoname db", time.Since(start))
	}()

	_, err := fileExists(filePath)
	if err != nil {
		return nil, err
	}

	storeStr := "file::memory:?cache=shared"
	if runtime.GOOS == "windows" {
		storeStr = "file::memory:"
	}

	db, err := gorm.Open(sqlite.Open(storeStr), &gorm.Config{
		Logger:      logger.Default.LogMode(logger.Silent),
		PrepareStmt: true,
	})
	if err != nil {
		return nil, err
	}

	if err := setupInMemoryDBFromFile(db, filePath); err != nil {
		return nil, err
	}

	sql, err := db.DB()
	if err != nil {
		return nil, err
	}
	conns := runtime.NumCPU()
	sql.SetMaxOpenConns(conns)

	return db, nil
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

	// index geoname_id and country_iso_code field
	err = db.Exec("CREATE INDEX idx_geonames_country_iso_code ON geonames(country_iso_code);").Error
	if err != nil {
		log.Fatal(err)
	}

	err = db.Exec("CREATE INDEX idx_geonames_geoname_id ON geonames(geoname_id);").Error
	if err != nil {
		log.Fatal(err)
	}

	return nil
}
