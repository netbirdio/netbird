//go:build (linux && !android) || freebsd

package system

import (
	"bufio"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

func readOsReleaseFile() (osName string, osVer string) {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		log.Warnf("failed to open file /etc/os-release: %s", err)
		return "", ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NAME=") {
			osName = strings.ReplaceAll(strings.Split(line, "=")[1], "\"", "")
			continue
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			osVer = strings.ReplaceAll(strings.Split(line, "=")[1], "\"", "")
			continue
		}

		if osName != "" && osVer != "" {
			break
		}
	}
	return
}
