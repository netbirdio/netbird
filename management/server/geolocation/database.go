package geolocation

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	geoLiteCityTarGZURL     = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City/download?suffix=tar.gz"
	geoLiteCityZipURL       = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City-CSV/download?suffix=zip"
	geoLiteCitySha256TarURL = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City/download?suffix=tar.gz.sha256"
	geoLiteCitySha256ZipURL = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City-CSV/download?suffix=zip.sha256"
	geoLiteCityMMDB         = "GeoLite2-City.mmdb"
	geoLiteCityCSV          = "GeoLite2-City-Locations-en.csv"

	geonamesCsvFields = 14
)

// downloadMMDB downloads the MaxMind city database and stores it as mmdbFile in dataDir.
func downloadMMDB(ctx context.Context, dataDir, mmdbFile string) error {
	extractFunc := func(src string, dst string) error {
		if err := decompressTarGzFile(src, dst); err != nil {
			return err
		}
		return copyFile(path.Join(dst, geoLiteCityMMDB), path.Join(dataDir, mmdbFile))
	}
	return loadDatabase(ctx, geoLiteCitySha256TarURL, geoLiteCityTarGZURL, extractFunc)
}

// downloadGeonamesDB downloads the city locations CSV and imports it into geonamesdbFile in dataDir.
func downloadGeonamesDB(ctx context.Context, dataDir, geonamesdbFile string) error {
	extractFunc := func(src string, dst string) error {
		if err := decompressZipFile(src, dst); err != nil {
			return err
		}
		extractedCsvFile := path.Join(dst, geoLiteCityCSV)
		return importCsvToSqlite(dataDir, extractedCsvFile, geonamesdbFile)
	}
	return loadDatabase(ctx, geoLiteCitySha256ZipURL, geoLiteCityZipURL, extractFunc)
}

// loadDatabase downloads a file from the specified URL and verifies its checksum.
// It then calls the extract function to perform additional processing on the extracted files.
func loadDatabase(ctx context.Context, checksumURL string, fileURL string, extractFunc func(src string, dst string) error) error {
	temp, err := os.MkdirTemp(os.TempDir(), "geolite")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)

	checksumFilename, err := getFilenameFromURL(ctx, checksumURL)
	if err != nil {
		return err
	}
	checksumFile := path.Join(temp, checksumFilename)

	checksumCtx, cancel := context.WithTimeout(ctx, headRequestTimeout)
	err = downloadFile(checksumCtx, checksumURL, checksumFile)
	cancel()
	if err != nil {
		return err
	}

	sha256sum, err := loadChecksumFromFile(checksumFile)
	if err != nil {
		return err
	}

	dbFilename, err := getFilenameFromURL(ctx, fileURL)
	if err != nil {
		return err
	}
	dbFile := path.Join(temp, dbFilename)

	err = downloadFile(ctx, fileURL, dbFile)
	if err != nil {
		return err
	}

	if err := verifyChecksum(dbFile, sha256sum); err != nil {
		return err
	}

	return extractFunc(dbFile, temp)
}

// importCsvToSqlite imports a CSV file into a SQLite database.
func importCsvToSqlite(dataDir string, csvFile string, geonamesdbFile string) error {
	geonames, err := loadGeonamesCsv(csvFile)
	if err != nil {
		return err
	}

	db, err := gorm.Open(sqlite.Open(path.Join(dataDir, geonamesdbFile)), &gorm.Config{
		Logger:          logger.Default.LogMode(logger.Silent),
		CreateBatchSize: 1000,
	})
	if err != nil {
		return err
	}
	defer func() {
		sql, err := db.DB()
		if err != nil {
			return
		}
		sql.Close()
	}()

	if err := db.AutoMigrate(&GeoNames{}); err != nil {
		return err
	}

	return db.Create(geonames).Error
}

func loadGeonamesCsv(filepath string) ([]GeoNames, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var geoNames []GeoNames
	for index, record := range records {
		if index == 0 {
			continue
		}
		if len(record) < geonamesCsvFields {
			return nil, fmt.Errorf("geonames csv record %d has %d fields, want at least %d", index, len(record), geonamesCsvFields)
		}

		geoNameID, err := strconv.Atoi(record[0])
		if err != nil {
			return nil, err
		}

		geoName := GeoNames{
			GeoNameID:           geoNameID,
			LocaleCode:          record[1],
			ContinentCode:       record[2],
			ContinentName:       record[3],
			CountryIsoCode:      record[4],
			CountryName:         record[5],
			Subdivision1IsoCode: record[6],
			Subdivision1Name:    record[7],
			Subdivision2IsoCode: record[8],
			Subdivision2Name:    record[9],
			CityName:            record[10],
			MetroCode:           record[11],
			TimeZone:            record[12],
			IsInEuropeanUnion:   record[13],
		}
		geoNames = append(geoNames, geoName)
	}

	return geoNames, nil
}

// copyFile performs a file copy operation from the source file to the destination.
func copyFile(src string, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	return nil
}
