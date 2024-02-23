package geolocation

import (
	"path"
)

const (
	geoLiteCityTarGZURL     = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City/download?suffix=tar.gz"
	geoLiteCityZipURL       = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City-CSV/download?suffix=zip"
	geoLiteCitySha256TarURL = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City/download?suffix=tar.gz.sha256"
	geoLiteCitySha256ZipURL = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City-CSV/download?suffix=zip.sha256"
)

// loadMaxMindDatabases loads the MaxMind databases.
func loadMaxMindDatabases(dataDir string) error {
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
		// download and load databases
	}

	return nil
}
