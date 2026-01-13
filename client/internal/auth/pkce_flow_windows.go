//go:build windows

package auth

import (
	"bufio"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// getSystemExcludedPortRanges retrieves the excluded port ranges from Windows using netsh.
func getSystemExcludedPortRanges() []excludedPortRange {
	ranges, err := getExcludedPortRangesFromNetsh()
	if err != nil {
		log.Debugf("failed to get Windows excluded port ranges: %v", err)
		return nil
	}

	return ranges
}

// getExcludedPortRangesFromNetsh retrieves excluded port ranges using netsh command.
func getExcludedPortRangesFromNetsh() ([]excludedPortRange, error) {
	cmd := exec.Command("netsh", "interface", "ipv4", "show", "excludedportrange", "protocol=tcp")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netsh command: %w", err)
	}

	return parseExcludedPortRanges(string(output))
}

// parseExcludedPortRanges parses the output of the netsh command to extract port ranges.
func parseExcludedPortRanges(output string) ([]excludedPortRange, error) {
	var ranges []excludedPortRange
	scanner := bufio.NewScanner(strings.NewReader(output))

	foundHeader := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.Contains(line, "Start Port") && strings.Contains(line, "End Port") {
			foundHeader = true
			continue
		}

		if !foundHeader {
			continue
		}

		if strings.Contains(line, "----------") {
			continue
		}

		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		startPort, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		endPort, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}

		ranges = append(ranges, excludedPortRange{start: startPort, end: endPort})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan output: %w", err)
	}

	return ranges, nil
}
