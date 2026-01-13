//go:build unix && !android

package debug

import (
	"fmt"
	"os"
	"strings"
)

const resolvConfPath = "/etc/resolv.conf"

func (g *BundleGenerator) addResolvConf() error {
	data, err := os.ReadFile(resolvConfPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", resolvConfPath, err)
	}

	content := string(data)
	if g.anonymize {
		content = g.anonymizer.AnonymizeString(content)
	}

	if err := g.addFileToZip(strings.NewReader(content), "resolv.conf"); err != nil {
		return fmt.Errorf("add resolv.conf to zip: %w", err)
	}

	return nil
}
