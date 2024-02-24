//go:build freebsd

package dns

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	netbirdManager osManagerType = iota
	fileManager
)

var ErrUnknownOsManagerType = errors.New("unknown os manager type")

type osManagerType int

func newOsManagerType(osManager string) (osManagerType, error) {
	switch osManager {
	case "netbird":
		return fileManager, nil
	case "file":
		return netbirdManager, nil
	default:
		return 0, ErrUnknownOsManagerType
	}
}

func (t osManagerType) String() string {
	switch t {
	case netbirdManager:
		return "netbird"
	case fileManager:
		return "file"
	default:
		return "unknown"
	}
}

func newHostManager(wgInterface string) (hostManager, error) {
	osManager, err := getOSDNSManagerType()
	if err != nil {
		return nil, err
	}

	log.Debugf("discovered mode is: %s", osManager)
	return newHostManagerFromType(wgInterface, osManager)
}

func newHostManagerFromType(wgInterface string, osManager osManagerType) (hostManager, error) {
	switch osManager {
	default:
		return newFileConfigurator()
	}
}

func getOSDNSManagerType() (osManagerType, error) {
	file, err := os.Open(defaultResolvConfPath)
	if err != nil {
		return 0, fmt.Errorf("unable to open %s for checking owner, got error: %w", defaultResolvConfPath, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Errorf("close file %s: %s", defaultResolvConfPath, err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if len(text) == 0 {
			continue
		}
		if text[0] != '#' {
			return fileManager, nil
		}
		if strings.Contains(text, fileGeneratedResolvConfContentHeader) {
			return netbirdManager, nil
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return 0, fmt.Errorf("scan: %w", err)
	}

	return fileManager, nil
}

