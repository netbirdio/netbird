package geolocation

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
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

var (
	mmdbTarGZURL  = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City/download?suffix=tar.gz"
	mmdbSha256URL = "https://pkgs.netbird.io/geolocation-dbs/GeoLite2-City/download?suffix=tar.gz.sha256"
)

const (
	mmdbInnerName = "GeoLite2-City.mmdb"

	downloadTimeout = 2 * time.Minute
	maxMMDBSize     = 256 << 20 // 256 MB
)

// downloadMMDB downloads the database named datedName from pkgs.netbird.io
// into dataDir with SHA256 verification and returns the final path.
func downloadMMDB(ctx context.Context, logger *log.Logger, client *http.Client, dataDir, datedName string) (string, error) {
	mmdbPath := filepath.Join(dataDir, deriveMMDBFilename(datedName))

	tmp, err := os.MkdirTemp("", "geolite-proxy-*")
	if err != nil {
		return "", fmt.Errorf("create temp directory: %w", err)
	}
	defer os.RemoveAll(tmp)

	checksumFile := filepath.Join(tmp, "checksum.sha256")
	if err := downloadToFile(ctx, client, mmdbSha256URL, checksumFile); err != nil {
		return "", fmt.Errorf("download checksum: %w", err)
	}

	expectedHash, err := readChecksumFile(checksumFile)
	if err != nil {
		return "", fmt.Errorf("read checksum: %w", err)
	}

	tarFile := filepath.Join(tmp, filepath.Base(datedName))
	logger.Debugf("downloading geolocation database (%s)", datedName)
	if err := downloadToFile(ctx, client, mmdbTarGZURL, tarFile); err != nil {
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

func fetchRemoteFilename(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req) //nolint:gosec
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HEAD request: HTTP %d", resp.StatusCode)
	}

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

func downloadToFile(ctx context.Context, client *http.Client, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req) //nolint:gosec
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
	if _, err := io.Copy(f, io.LimitReader(resp.Body, maxMMDBSize)); err != nil {
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
