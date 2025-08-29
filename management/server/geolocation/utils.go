package geolocation

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
)

// decompressTarGzFile decompresses a .tar.gz file.
func decompressTarGzFile(filepath, destDir string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}

		if header.Typeflag == tar.TypeReg {
			outFile, err := os.Create(path.Join(destDir, path.Base(header.Name)))
			if err != nil {
				return err
			}

			_, err = io.Copy(outFile, tarReader) // #nosec G110
			outFile.Close()
			if err != nil {
				return err
			}
		}

	}

	return nil
}

// decompressZipFile decompresses a .zip file.
func decompressZipFile(filepath, destDir string) error {
	r, err := zip.OpenReader(filepath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		outFile, err := os.Create(path.Join(destDir, path.Base(f.Name)))
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc) // #nosec G110
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

// calculateFileSHA256 calculates the SHA256 checksum of a file.
func calculateFileSHA256(filepath string) ([]byte, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// loadChecksumFromFile loads the first checksum from a file.
func loadChecksumFromFile(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) > 0 {
			return parts[0], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", nil
}

// verifyChecksum compares the calculated SHA256 checksum of a file against the expected checksum.
func verifyChecksum(filepath, expectedChecksum string) error {
	calculatedChecksum, err := calculateFileSHA256(filepath)

	fileCheckSum := fmt.Sprintf("%x", calculatedChecksum)
	if err != nil {
		return err
	}

	if fileCheckSum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, fileCheckSum)
	}

	return nil
}

// downloadFile downloads a file from a URL and saves it to a local file path.
func downloadFile(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected error occurred while downloading the file: %s", string(bodyBytes))
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, bytes.NewBuffer(bodyBytes))
	return err
}

func getFilenameFromURL(url string) (string, error) {
	resp, err := http.Head(url)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	_, params, err := mime.ParseMediaType(resp.Header["Content-Disposition"][0])
	if err != nil {
		return "", err
	}

	filename := params["filename"]

	return filename, nil
}
