package update

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/updatemanager/installer"
	"github.com/netbirdio/netbird/util"
)

var (
	tempDirFlag    string
	installerFile  string
	serviceDirFlag string
	dryRunFlag     bool
)

func init() {
	flag.StringVar(&tempDirFlag, "temp-dir", "", "temporary dir")
	flag.StringVar(&installerFile, "installer-file", "", "installer file")
	flag.StringVar(&serviceDirFlag, "service-dir", "", "service directory")
	flag.BoolVar(&dryRunFlag, "dry-run", false, "dry run the update process without making any changes")
}

// IsUpdateBinary checks if the current executable is named "update" or "update.exe"
func IsUpdateBinary() bool {
	// Remove extension for cross-platform compatibility
	execPath, err := os.Executable()
	if err != nil {
		return false
	}
	baseName := filepath.Base(execPath)
	name := strings.TrimSuffix(baseName, filepath.Ext(baseName))

	return name == installer.UpdaterBinaryNameWithoutExtension()
}

func Execute() {
	ui := NewUI()

	// Create a context with timeout for the entire update process
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	ui.ShowUpdateProgress(ctx)
	// Run the update function in a goroutine
	go func() {
		defer cancel()

		if err := updateFunc(); err != nil {
			log.Errorf("update failed: %v", err)
			// The UI will handle the error display through context cancellation
			return
		}

		// Success - the UI will automatically close the window
		log.Infof("update completed successfully")
	}()

	// Start the Fyne app event loop (blocks until window is closed or context is done)
	ui.Run()
}

func updateFunc() error {
	if err := setupLogToFile(tempDirFlag); err != nil {
		return err
	}

	log.Infof("updater started: %s", serviceDirFlag)
	updater := installer.NewWithDir(tempDirFlag)
	if err := updater.Setup(context.Background(), dryRunFlag, installerFile, serviceDirFlag); err != nil {
		log.Errorf("failed to update application: %v", err)
		return err
	}
	return nil
}

func setupLogToFile(dir string) error {
	logFile := filepath.Join(dir, installer.LogFile)

	if _, err := os.Stat(logFile); err == nil {
		if err := os.Remove(logFile); err != nil {
			log.Errorf("failed to remove existing log file: %v\n", err)
		}
	}

	return util.InitLog("debug", util.LogConsole, logFile)
}
