package installer

import (
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

func LogFilePath(installerPath string) string {
	installerDir := filepath.Dir(installerPath)
	logFile := filepath.Join(installerDir, "install.log")

	if _, err := os.Stat(logFile); err == nil {
		if err := os.Remove(logFile); err != nil {
			log.Errorf("failed to remove existing log file: %v\n", err)
		}
	}

	return logFile
}
