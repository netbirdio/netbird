package geolocation

import (
	"fmt"
	"net/url"
	"os"
	"path"
)

const (
	geoLiteCityTarGZURL     = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City/download?suffix=tar.gz"
	geoLiteCityZipURL       = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City-CSV/download?suffix=zip"
	geoLiteCitySha256TarURL = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City/download?suffix=tar.gz.sha256"
	geoLiteCitySha256ZipURL = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City-CSV/download?suffix=zip.sha256"
)

// LoadMaxMindDatabases loads the MaxMind databases.
func LoadMaxMindDatabases(dataDir string) error {
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
				// move the extracted db file to management data directory
				return os.Rename(path.Join(dst, MMDBFileName), path.Join(dataDir, MMDBFileName))
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
				// TODO: generate sqlite db from processed csv file
				return nil
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
