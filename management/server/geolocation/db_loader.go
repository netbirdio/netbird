package geolocation

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
)

const (
	geoLiteCityTarGZURL     = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City/download?suffix=tar.gz"
	geoLiteCityZipURL       = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City-CSV/download?suffix=zip"
	geoLiteCitySha256TarURL = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City/download?suffix=tar.gz.sha256"
	geoLiteCitySha256ZipURL = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City-CSV/download?suffix=zip.sha256"
)

// LoadMaxMindDatabases loads the MaxMind databases.
func LoadMaxMindDatabases(dataDir string) error {
	var reload bool

	_, err := fileExists(path.Join(dataDir, MMDBFileName))
	if err != nil {
		reload = true
	}

	_, err = fileExists(path.Join(dataDir, GeoSqliteDBFile))
	if err != nil {
		reload = true
	}

	if reload {
		if err := loadGeoLiteBinaryDatabase(dataDir); err != nil {
			return fmt.Errorf("error loading geolite binary database: %v", err)
		}
	}

	return nil
}

func loadGeoLiteBinaryDatabase(dataDir string) error {
	temp, err := os.MkdirTemp(os.TempDir(), strings.TrimPrefix(MMDBFileName, ".mmdb"))
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)

	checksumFile := path.Join(temp, getFileName(geoLiteCitySha256TarURL))
	err = downloadFile(geoLiteCitySha256TarURL, checksumFile)
	if err != nil {
		return err
	}

	sha256sum, err := loadChecksumFromFile(checksumFile)
	if err != nil {
		return err
	}

	binaryDbFile := path.Join(temp, getFileName(geoLiteCityTarGZURL))
	err = downloadFile(geoLiteCityTarGZURL, binaryDbFile)
	if err != nil {
		return err
	}

	if err := verifyChecksum(binaryDbFile, sha256sum); err != nil {
		return err
	}

	if err := decompressTarGzFile(binaryDbFile, temp); err != nil {
		return err
	}

	// move the extracted db file to management data directory
	return os.Rename(path.Join(temp, MMDBFileName), path.Join(dataDir, MMDBFileName))
}

func getFileName(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		panic(err)
	}

	ext := u.Query().Get("suffix")
	fileName := fmt.Sprintf("%s.%s", path.Base(u.Path), ext)
	return fileName
}
