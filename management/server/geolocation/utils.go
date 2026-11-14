package geolocation

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

// A stalled connection must not block management startup. Filename lookups only read
// headers, so they get a fixed timeout. Downloads can be slow on constrained links, so they
// are cancelled only when no data arrives for downloadIdleTimeout.
var (
	headRequestTimeout  = 30 * time.Second
	downloadIdleTimeout = time.Minute
)

var errDownloadStalled = errors.New("download stalled")

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
func downloadFile(ctx context.Context, url, filepath string) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	idle := time.AfterFunc(downloadIdleTimeout, func() { cancel(errDownloadStalled) })
	defer idle.Stop()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return downloadError(ctx, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(&idleReader{r: resp.Body, idle: idle})
	if err != nil {
		return downloadError(ctx, err)
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

// idleReadSize caps a single read, because a chunked body keeps reading from the network
// until the buffer is full and would otherwise outlast the idle deadline on a slow link.
const idleReadSize = 32 << 10

// idleReader pushes the idle deadline back whenever data arrives.
type idleReader struct {
	r    io.Reader
	idle *time.Timer
}

func (r *idleReader) Read(p []byte) (int, error) {
	if len(p) > idleReadSize {
		p = p[:idleReadSize]
	}
	n, err := r.r.Read(p)
	if n > 0 {
		r.idle.Reset(downloadIdleTimeout)
	}
	return n, err
}

// downloadError names a stall, which would otherwise surface as a bare "context canceled".
func downloadError(ctx context.Context, err error) error {
	if errors.Is(context.Cause(ctx), errDownloadStalled) {
		return fmt.Errorf("no data received for %s: %w", downloadIdleTimeout, err)
	}
	return err
}

func getFilenameFromURL(ctx context.Context, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, headRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	contentDisposition := resp.Header.Get("Content-Disposition")
	if contentDisposition == "" {
		return "", fmt.Errorf("no Content-Disposition header in response from %s", url)
	}

	_, params, err := mime.ParseMediaType(contentDisposition)
	if err != nil {
		return "", err
	}

	filename := params["filename"]

	return filename, nil
}
