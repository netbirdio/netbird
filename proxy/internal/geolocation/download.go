package geolocation

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	mmdbTarGZURL  = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City/download?suffix=tar.gz"
	mmdbSha256URL = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City/download?suffix=tar.gz.sha256"
	mmdbInnerName = "GeoLite2-City.mmdb"

	downloadTimeout = 2 * time.Minute
	maxMMDBSize     = 256 << 20 // 256 MB
)

// ensureMMDB checks for an existing MMDB file in dataDir. If none is found,
// it downloads from pkgs.netbird.io with SHA256 verification.
func ensureMMDB(logger *log.Logger, dataDir string) (string, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", fmt.Errorf("create geo data directory %s: %w", dataDir, err)
	}

	pattern := filepath.Join(dataDir, mmdbGlob)
	if files, _ := filepath.Glob(pattern); len(files) > 0 {
		mmdbPath := files[len(files)-1]
		logger.Debugf("using existing geolocation database: %s", mmdbPath)
		return mmdbPath, nil
	}

	logger.Info("geolocation database not found, downloading from pkgs.netbird.io")
	return downloadMMDB(logger, dataDir)
}

func downloadMMDB(logger *log.Logger, dataDir string) (string, error) {
	client := &http.Client{Timeout: downloadTimeout}

	datedName, err := fetchRemoteFilename(client, mmdbTarGZURL)
	if err != nil {
		return "", fmt.Errorf("get remote filename: %w", err)
	}

	mmdbFilename := deriveMMDBFilename(datedName)
	mmdbPath := filepath.Join(dataDir, mmdbFilename)

	tmp, err := os.MkdirTemp("", "geolite-proxy-*")
	if err != nil {
		return "", fmt.Errorf("create temp directory: %w", err)
	}
	defer os.RemoveAll(tmp)

	checksumFile := filepath.Join(tmp, "checksum.sha256")
	if err := downloadToFile(client, mmdbSha256URL, checksumFile); err != nil {
		return "", fmt.Errorf("download checksum: %w", err)
	}

	expectedHash, err := readChecksumFile(checksumFile)
	if err != nil {
		return "", fmt.Errorf("read checksum: %w", err)
	}

	tarFile := filepath.Join(tmp, datedName)
	logger.Debugf("downloading geolocation database (%s)", datedName)
	if err := downloadToFile(client, mmdbTarGZURL, tarFile); err != nil {
		return "", fmt.Errorf("download database: %w", err)
	}

	if err := verifySHA256(tarFile, expectedHash); err != nil {
		return "", fmt.Errorf("verify database checksum: %w", err)
	}

	if err := extractMMDBFromTarGZ(tarFile, mmdbPath); err != nil {
		return "", fmt.Errorf("extract database: %w", err)
	}

	logger.Infof("geolocation database downloaded: %s", mmdbPath)
	return mmdbPath, nil
}

// deriveMMDBFilename converts a tar.gz filename to an MMDB filename.
// Example: GeoLite2-City_20240101.tar.gz -> GeoLite2-City_20240101.mmdb
func deriveMMDBFilename(tarName string) string {
	base, _, _ := strings.Cut(tarName, ".")
	if !strings.Contains(base, "_") {
		return "GeoLite2-City.mmdb"
	}
	return base + ".mmdb"
}

func fetchRemoteFilename(client *http.Client, url string) (string, error) {
	resp, err := client.Head(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	cd := resp.Header.Get("Content-Disposition")
	if cd == "" {
		return "", errors.New("no Content-Disposition header")
	}

	_, params, err := mime.ParseMediaType(cd)
	if err != nil {
		return "", fmt.Errorf("parse Content-Disposition: %w", err)
	}

	name := filepath.Base(params["filename"])
	if name == "" || name == "." {
		return "", errors.New("no filename in Content-Disposition")
	}
	return name, nil
}

func downloadToFile(client *http.Client, url, dest string) error {
	resp, err := client.Get(url) //nolint:gosec
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	f, err := os.Create(dest) //nolint:gosec
	if err != nil {
		return err
	}
	defer f.Close()

	// Cap download at 256 MB to prevent unbounded reads from a compromised server.
	if _, err := io.Copy(f, io.LimitReader(resp.Body, 256<<20)); err != nil {
		return err
	}
	return nil
}

func readChecksumFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) > 0 {
			return parts[0], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("empty checksum file")
}

func verifySHA256(path, expected string) error {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}

	actual := fmt.Sprintf("%x", h.Sum(nil))
	if actual != expected {
		return fmt.Errorf("SHA256 mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

func extractMMDBFromTarGZ(tarGZPath, destPath string) error {
	f, err := os.Open(tarGZPath) //nolint:gosec
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}

		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == mmdbInnerName {
			if hdr.Size < 0 || hdr.Size > maxMMDBSize {
				return fmt.Errorf("mmdb entry size %d exceeds limit %d", hdr.Size, maxMMDBSize)
			}
			if err := extractToFileAtomic(io.LimitReader(tr, hdr.Size), destPath); err != nil {
				return err
			}
			return nil
		}
	}

	return fmt.Errorf("%s not found in archive", mmdbInnerName)
}

// extractToFileAtomic writes r to a temporary file in the same directory as
// destPath, then renames it into place so a crash never leaves a truncated file.
func extractToFileAtomic(r io.Reader, destPath string) error {
	dir := filepath.Dir(destPath)
	tmp, err := os.CreateTemp(dir, ".mmdb-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := io.Copy(tmp, r); err != nil { //nolint:gosec // G110: caller bounds with LimitReader
		if closeErr := tmp.Close(); closeErr != nil {
			log.Debugf("failed to close temp file %s: %v", tmpPath, closeErr)
		}
		if removeErr := os.Remove(tmpPath); removeErr != nil {
			log.Debugf("failed to remove temp file %s: %v", tmpPath, removeErr)
		}
		return fmt.Errorf("write mmdb: %w", err)
	}
	if err := tmp.Close(); err != nil {
		if removeErr := os.Remove(tmpPath); removeErr != nil {
			log.Debugf("failed to remove temp file %s: %v", tmpPath, removeErr)
		}
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		if removeErr := os.Remove(tmpPath); removeErr != nil {
			log.Debugf("failed to remove temp file %s: %v", tmpPath, removeErr)
		}
		return fmt.Errorf("rename to %s: %w", destPath, err)
	}
	return nil
}
