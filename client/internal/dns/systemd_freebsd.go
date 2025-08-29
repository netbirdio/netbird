package dns

import (
	"errors"
	"fmt"
)

var errNotImplemented = errors.New("not implemented")

func newSystemdDbusConfigurator(string) (restoreHostManager, error) {
	return nil, fmt.Errorf("systemd dns management: %w on freebsd", errNotImplemented)
}

func isSystemdResolvedRunning() bool {
	return false
}

func isSystemdResolveConfMode() bool {
	return false
}
