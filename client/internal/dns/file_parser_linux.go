package dns

import (
	"fmt"
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

func parseDefaultResolvConf() (*resolvConf, error) {
	return parseResolvConfFile(defaultResolvConfPath)
}

func parseBackupResolvConf() (*resolvConf, error) {
	return parseResolvConfFile(fileDefaultResolvConfBackupLocation)
}

func parseResolvConfFile(resolvConfFile string) (*resolvConf, error) {
	file, err := os.Open(resolvConfFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cur, err := os.ReadFile(resolvConfFile)
	if err != nil {
		return nil, err
	}

	if len(cur) == 0 {
		return nil, fmt.Errorf("file is empty")
	}

	rconf := &resolvConf{
		nameServers: make([]string, 0),
		others:      make([]string, 0),
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
			log.Debugf("found search domains: %s", line)
			splitLines := strings.Fields(line)
			if len(splitLines) < 2 {
				continue
			}

			rconf.searchDomains = splitLines[1:]
			log.Debugf("search domains: %s", rconf.searchDomains)
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
