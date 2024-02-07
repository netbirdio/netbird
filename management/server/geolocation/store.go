package geolocation

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	geoSqliteDBFile = "geonames.db"
)

// SqliteStore represents a location storage backed by a Sqlite DB.
type SqliteStore struct {
	db       *gorm.DB
	filePath string
	mux      *sync.RWMutex
}

func NewSqliteStore(dataDir string) (*SqliteStore, error) {
	db, err := connectDB(dataDir)
	if err != nil {
		return nil, err
	}

	return &SqliteStore{
		db:       db,
		filePath: filepath.Join(dataDir, geoSqliteDBFile),
		mux:      &sync.RWMutex{},
	}, nil
}

// GetAllCountries returns a list of all countries in the store.
func (s *SqliteStore) GetAllCountries() ([]Country, error) {
	s.mux.Lock()
	defer s.mux.Unlock()

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
	s.mux.Lock()
	defer s.mux.Unlock()

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

func (s *SqliteStore) reload() error {
	s.mux.Lock()
	defer s.mux.Unlock()

	log.Infof("Reloading '%s'", s.filePath)

	newDb, err := connectDB(s.filePath)
	if err != nil {
		return err
	}

	_ = s.close()
	s.db = newDb

	log.Infof("Successfully reloaded '%s'", s.filePath)
	return nil
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
func connectDB(dataDir string) (*gorm.DB, error) {
	start := time.Now()
	defer func() {
		log.Debugf("took %v to setup geoname db", time.Since(start))
	}()

	file := filepath.Join(dataDir, geoSqliteDBFile)
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
