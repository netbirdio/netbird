//go:build windows

package inspect

import (
	"fmt"
	"os"
)

// signalReload is not supported on Windows. Envoy must be restarted.
func signalReload(_ *os.Process) error {
	return fmt.Errorf("envoy config reload via signal not supported on Windows")
}
