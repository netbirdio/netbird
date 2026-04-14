//go:build android

package debug

import (
	"fmt"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

func (g *BundleGenerator) addPlatformLog() error {
	cmd := exec.Command("/system/bin/logcat", "-d")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("run logcat: %w", err)
	}

	var logReader *strings.Reader
	if g.anonymize {
		anonymized := g.anonymizer.AnonymizeString(string(out))
		logReader = strings.NewReader(anonymized)
	} else {
		logReader = strings.NewReader(string(out))
	}

	if err := g.addFileToZip(logReader, "logcat.txt"); err != nil {
		return fmt.Errorf("add logcat to zip: %w", err)
	}

	log.Debugf("added logcat output to debug bundle (%d bytes)", len(out))
	return nil
}
