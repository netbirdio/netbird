package dns

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const (
	defaultResolvConfPath = "/etc/resolv.conf"
)

func resolvConfEntries() (searchDomains, nameServers, others []string, err error) {
	return parseResolvConf(defaultResolvConfPath)
}

func parseResolvConf(resolvconfFile string) (searchDomains, nameServers, others []string, err error) {
	file, err := os.Open(resolvconfFile)
	if err != nil {
		err = fmt.Errorf(`could not read existing resolv.conf`)
		return
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	for {
		lineBytes, isPrefix, readErr := reader.ReadLine()
		if readErr != nil {
			break
		}

		if isPrefix {
			err = fmt.Errorf(`resolv.conf line too long`)
			return
		}

		line := strings.TrimSpace(string(lineBytes))

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

			searchDomains = splitLines[1:]
			continue
		}

		if strings.HasPrefix(line, "nameserver") {
			splitLines := strings.Fields(line)
			if len(splitLines) != 2 {
				continue
			}
			nameServers = append(nameServers, splitLines[1])
			continue
		}

		if line != "" {
			others = append(others, line)
		}
	}
	return
}
