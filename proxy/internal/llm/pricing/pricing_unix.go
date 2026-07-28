//go:build unix

package pricing

import (
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// maxPricingBytes caps the size of the pricing YAML on read so a hostile or
// runaway file cannot exhaust process memory during reload. 1 MiB is several
// orders of magnitude larger than any reasonable pricing table.
const maxPricingBytes int64 = 1 << 20

// loadPricing opens the file with O_NOFOLLOW, fstats the open descriptor,
// and parses from that same descriptor. Never re-opens by path so a
// mid-read rename or symlink swap cannot substitute content. Bytes are
// capped at maxPricingBytes so the loader cannot be coerced into reading an
// unbounded file.
func loadPricing(path string) (*Table, time.Time, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Debugf("close pricing file %s: %v", path, cerr)
		}
	}()

	info, err := f.Stat()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("fstat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, time.Time{}, fmt.Errorf("pricing file %s is not a regular file", path)
	}

	data, err := io.ReadAll(io.LimitReader(f, maxPricingBytes+1))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > maxPricingBytes {
		return nil, time.Time{}, fmt.Errorf("pricing file %s exceeds %d bytes", path, maxPricingBytes)
	}

	table, err := parsePricingBytes(data)
	if err != nil {
		return nil, time.Time{}, err
	}
	return table, info.ModTime(), nil
}

// statMtime returns the mtime of the file at path. It uses lstat semantics
// via os.Lstat so a symlink swap is detected even though O_NOFOLLOW will
// later reject the open.
func statMtime(path string) (time.Time, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return time.Time{}, fmt.Errorf("lstat %s: %w", path, err)
	}
	return info.ModTime(), nil
}
