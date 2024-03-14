package geolocation

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/url"
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
)

// loadGeolocationDatabases loads the MaxMind databases.
func loadGeolocationDatabases(dataDir string) error {
	files := []string{MMDBFileName, GeoSqliteDBFile}
	for _, file := range files {
		exists, _ := fileExists(path.Join(dataDir, file))
		if exists {
			continue
		}

		switch file {
		case MMDBFileName:
			extractFunc := func(src string, dst string) error {
				if err := decompressTarGzFile(src, dst); err != nil {
					return err
				}
				return copyFile(path.Join(dst, MMDBFileName), path.Join(dataDir, MMDBFileName))
			}
			if err := loadDatabase(
				geoLiteCitySha256TarURL,
				geoLiteCityTarGZURL,
				extractFunc,
			); err != nil {
				return err
			}

		case GeoSqliteDBFile:
			extractFunc := func(src string, dst string) error {
				if err := decompressZipFile(src, dst); err != nil {
					return err
				}
				extractedCsvFile := path.Join(dst, "GeoLite2-City-Locations-en.csv")
				return importCsvToSqlite(dataDir, extractedCsvFile)
			}

			if err := loadDatabase(
				geoLiteCitySha256ZipURL,
				geoLiteCityZipURL,
				extractFunc,
			); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadDatabase downloads a file from the specified URL and verifies its checksum.
// It then calls the extract function to perform additional processing on the extracted files.
func loadDatabase(checksumURL string, fileURL string, extractFunc func(src string, dst string) error) error {
	temp, err := os.MkdirTemp(os.TempDir(), "geolite")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)

	checksumFile := path.Join(temp, getDatabaseFileName(checksumURL))
	err = downloadFile(checksumURL, checksumFile)
	if err != nil {
		return err
	}

	sha256sum, err := loadChecksumFromFile(checksumFile)
	if err != nil {
		return err
	}

	dbFile := path.Join(temp, getDatabaseFileName(fileURL))
	err = downloadFile(fileURL, dbFile)
	if err != nil {
		return err
	}

	if err := verifyChecksum(dbFile, sha256sum); err != nil {
		return err
	}

	return extractFunc(dbFile, temp)
}

// importCsvToSqlite imports a CSV file into a SQLite database.
func importCsvToSqlite(dataDir string, csvFile string) error {
	geonames, err := loadGeonamesCsv(csvFile)
	if err != nil {
		return err
	}

	db, err := gorm.Open(sqlite.Open(path.Join(dataDir, GeoSqliteDBFile)), &gorm.Config{
		Logger:          logger.Default.LogMode(logger.Silent),
		CreateBatchSize: 1000,
		PrepareStmt:     true,
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

// getDatabaseFileName extracts the file name from a given URL string.
func getDatabaseFileName(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		panic(err)
	}

	ext := u.Query().Get("suffix")
	fileName := fmt.Sprintf("%s.%s", path.Base(u.Path), ext)
	return fileName
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
