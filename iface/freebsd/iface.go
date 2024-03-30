package freebsd

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

type iface struct {
	Name    string
	MTU     int
	Group   string
	IPAddrs []string
}

func parseError(output []byte) error {
	// TODO: implement without allocations
	lines := string(output)

	if strings.Contains(lines, "does not exist") {
		return ErrDoesNotExist
	}

	return nil
}

func parseIfconfigOutput(output []byte) (*iface, error) {
	// TODO: implement without allocations
	lines := string(output)

	scanner := bufio.NewScanner(strings.NewReader(lines))

	var name, mtu, group string
	var ips []string

	for scanner.Scan() {
		line := scanner.Text()

		// If line contains ": flags", it's a line with interface information
		if strings.Contains(line, ": flags") {
			parts := strings.Fields(line)
			if len(parts) < 4 {
				return nil, fmt.Errorf("failed to parse line: %s", line)
			}
			name = strings.TrimSuffix(parts[0], ":")
			if strings.Contains(line, "mtu") {
				mtuIndex := 0
				for i, part := range parts {
					if part == "mtu" {
						mtuIndex = i
						break
					}
				}
				mtu = parts[mtuIndex+1]
			}
		}

		// If line contains "groups:", it's a line with interface group
		if strings.Contains(line, "groups:") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				return nil, fmt.Errorf("failed to parse line: %s", line)
			}
			group = parts[1]
		}

		// If line contains "inet ", it's a line with IP address
		if strings.Contains(line, "inet ") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				return nil, fmt.Errorf("failed to parse line: %s", line)
			}
			ips = append(ips, parts[1])
		}
	}

	if name == "" {
		return nil, fmt.Errorf("interface name not found in ifconfig output")
	}

	mtuInt, err := strconv.Atoi(mtu)
	if err != nil {
		return nil, fmt.Errorf("failed to parse MTU: %w", err)
	}

	return &iface{
		Name:    name,
		MTU:     mtuInt,
		Group:   group,
		IPAddrs: ips,
	}, nil
}

func parseIFName(output []byte) (string, error) {
	// TODO: implement without allocations
	lines := strings.Split(string(output), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return "", fmt.Errorf("no output returned")
	}

	fields := strings.Fields(lines[0])
	if len(fields) > 1 {
		return "", fmt.Errorf("invalid output")
	}

	return fields[0], nil
}
