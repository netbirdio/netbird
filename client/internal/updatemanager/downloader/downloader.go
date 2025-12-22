package downloader

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/version"
)

const (
	userAgent         = "NetBird agent installer/%s"
	DefaultRetryDelay = 3 * time.Second
)

func DownloadToFile(ctx context.Context, retryDelay time.Duration, url, dstFile string) error {
	log.Debugf("starting download from %s", url)

	out, err := os.Create(dstFile)
	if err != nil {
		return fmt.Errorf("failed to create destination file %q: %w", dstFile, err)
	}
	defer func() {
		if cerr := out.Close(); cerr != nil {
			log.Warnf("error closing file %q: %v", dstFile, cerr)
		}
	}()

	// First attempt
	err = downloadToFileOnce(ctx, url, out)
	if err == nil {
		log.Infof("successfully downloaded file to %s", dstFile)
		return nil
	}

	// If retryDelay is 0, don't retry
	if retryDelay == 0 {
		return err
	}

	log.Warnf("download failed, retrying after %v: %v", retryDelay, err)

	// Sleep before retry
	if sleepErr := sleepWithContext(ctx, retryDelay); sleepErr != nil {
		return fmt.Errorf("download cancelled during retry delay: %w", sleepErr)
	}

	// Truncate file before retry
	if err := out.Truncate(0); err != nil {
		return fmt.Errorf("failed to truncate file on retry: %w", err)
	}
	if _, err := out.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek to beginning of file: %w", err)
	}

	// Second attempt
	if err := downloadToFileOnce(ctx, url, out); err != nil {
		return fmt.Errorf("download failed after retry: %w", err)
	}

	log.Infof("successfully downloaded file to %s", dstFile)
	return nil
}

func DownloadToMemory(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add User-Agent header
	req.Header.Set("User-Agent", fmt.Sprintf(userAgent, version.NetbirdVersion()))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Warnf("error closing response body: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return data, nil
}

func downloadToFileOnce(ctx context.Context, url string, out *os.File) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add User-Agent header
	req.Header.Set("User-Agent", fmt.Sprintf(userAgent, version.NetbirdVersion()))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform HTTP request: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Warnf("error closing response body: %v", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	}

	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("failed to write response body to file: %w", err)
	}

	return nil
}

func sleepWithContext(ctx context.Context, duration time.Duration) error {
	select {
	case <-time.After(duration):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
