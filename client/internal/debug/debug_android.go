//go:build android

package debug

import (
	"fmt"
	"io"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

func (g *BundleGenerator) addPlatformLog() error {
	cmd := exec.Command("/system/bin/logcat", "-d")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("logcat stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start logcat: %w", err)
	}

	var logReader io.Reader = stdout
	if g.anonymize {
		var pw *io.PipeWriter
		logReader, pw = io.Pipe()
		go anonymizeLog(stdout, pw, g.anonymizer)
	}

	if err := g.addFileToZip(logReader, "logcat.txt"); err != nil {
		return fmt.Errorf("add logcat to zip: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("wait logcat: %w", err)
	}

	log.Debug("added logcat output to debug bundle")
	return nil
}
