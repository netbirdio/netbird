//go:build (linux && !android) || freebsd

package dns

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	defaultResolvConfPath = "/etc/resolv.conf"
)

type resolvConf struct {
	nameServers   []string
	searchDomains []string
	others        []string
}

func (r *resolvConf) String() string {
	return fmt.Sprintf("search domains: %v, name servers: %v, others: %s", r.searchDomains, r.nameServers, r.others)
}

func parseDefaultResolvConf() (*resolvConf, error) {
	return parseResolvConfFile(defaultResolvConfPath)
}

func parseBackupResolvConf() (*resolvConf, error) {
	return parseResolvConfFile(fileDefaultResolvConfBackupLocation)
}

func parseResolvConfFile(resolvConfFile string) (*resolvConf, error) {
	rconf := &resolvConf{
		searchDomains: make([]string, 0),
		nameServers:   make([]string, 0),
		others:        make([]string, 0),
	}

	file, err := os.Open(resolvConfFile)
	if err != nil {
		return rconf, fmt.Errorf("failed to open %s file: %w", resolvConfFile, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Errorf("failed closing %s: %s", resolvConfFile, err)
		}
	}()

	cur, err := os.ReadFile(resolvConfFile)
	if err != nil {
		return rconf, fmt.Errorf("failed to read %s file: %w", resolvConfFile, err)
	}

	if len(cur) == 0 {
		return rconf, fmt.Errorf("file is empty")
	}

	for _, line := range strings.Split(string(cur), "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "domain") {
			continue
		}

		if strings.HasPrefix(line, "options") && strings.Contains(line, "rotate") {
			line = strings.ReplaceAll(line, "rotate", "")
			splitLines := strings.Fields(line)
			if len(splitLines) == 1 {
				continue
			}
			line = strings.Join(splitLines, " ")
		}

		if strings.HasPrefix(line, "search") {
			splitLines := strings.Fields(line)
			if len(splitLines) < 2 {
				continue
			}

			rconf.searchDomains = splitLines[1:]
			continue
		}

		if strings.HasPrefix(line, "nameserver") {
			splitLines := strings.Fields(line)
			if len(splitLines) != 2 {
				continue
			}
			rconf.nameServers = append(rconf.nameServers, splitLines[1])
			continue
		}

		if line != "" {
			rconf.others = append(rconf.others, line)
		}
	}
	return rconf, nil
}

// removeFirstNbNameserver removes the given nameserver from the given file if it is in the first position
// and writes the file back to the original location
func removeFirstNbNameserver(filename string, nameserverIP netip.Addr) error {
	resolvConf, err := parseResolvConfFile(filename)
	if err != nil {
		return fmt.Errorf("parse backup resolv.conf: %w", err)
	}
	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read %s: %w", filename, err)
	}

	if len(resolvConf.nameServers) > 1 && resolvConf.nameServers[0] == nameserverIP.String() {
		newContent := strings.Replace(string(content), fmt.Sprintf("nameserver %s\n", nameserverIP), "", 1)

		stat, err := os.Stat(filename)
		if err != nil {
			return fmt.Errorf("stat %s: %w", filename, err)
		}
		if err := os.WriteFile(filename, []byte(newContent), stat.Mode()); err != nil {
			return fmt.Errorf("write %s: %w", filename, err)
		}

	}

	return nil
}
