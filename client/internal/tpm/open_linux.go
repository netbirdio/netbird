package tpm

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm/tpmutil"
)

// The kernel resource manager multiplexes clients and flushes what they leave behind,
// so it is tried before the raw device.
var devicePaths = []string{"/dev/tpmrm0", "/dev/tpm0"}

func open() (io.ReadWriteCloser, error) {
	if path := os.Getenv(DeviceEnv); path != "" {
		return tpmutil.OpenTPM(path)
	}
	var errs error
	for _, path := range devicePaths {
		rwc, err := tpmutil.OpenTPM(path)
		if err == nil {
			return rwc, nil
		}
		errs = errors.Join(errs, err)
	}
	return nil, fmt.Errorf("open TPM: %w", errs)
}
