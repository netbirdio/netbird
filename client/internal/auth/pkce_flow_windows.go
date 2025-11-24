//go:build windows

package auth

import (
	"fmt"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/registry"
)

// getSystemExcludedPortRanges retrieves the excluded port ranges from Windows.
func getSystemExcludedPortRanges() []excludedPortRange {
	ranges, err := getExcludedPortRangesFromRegistry()
	if err == nil && len(ranges) > 0 {
		return ranges
	}

	return ranges
}

// getExcludedPortRangesFromRegistry retrieves excluded port ranges from Windows registry.
func getExcludedPortRangesFromRegistry() ([]excludedPortRange, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		registry.QUERY_VALUE)
	if err != nil {
		return nil, fmt.Errorf("open registry key: %w", err)
	}
	defer func() {
		if err := k.Close(); err != nil {
			log.Debugf("failed to close registry key: %v", err)
		}
	}()

	reservedPorts, _, err := k.GetStringsValue("ReservedPorts")
	if err != nil {
		return nil, fmt.Errorf("read ReservedPorts: %w", err)
	}

	var ranges []excludedPortRange
	for _, portSpec := range reservedPorts {
		parts := strings.Split(portSpec, "-")
		if len(parts) != 2 {
			continue
		}

		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			continue
		}

		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			continue
		}

		ranges = append(ranges, excludedPortRange{start: start, end: end})
	}

	return ranges, nil
}
