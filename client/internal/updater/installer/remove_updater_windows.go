package installer

import (
	"errors"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	// The updater is the process that restarted the daemon, so when the daemon
	// cleans up at startup the updater is often still exiting and Windows refuses
	// to delete its locked image. These bound how long cleanup waits for it.
	updaterRemoveAttempts = 5
	updaterRemoveDelay    = 200 * time.Millisecond
)

// removeUpdaterBinary deletes the updater copy left in the temp dir, retrying
// while the still-exiting updater process holds its image. If it stays locked for
// the whole window the file is scheduled for deletion on the next reboot, so a
// locked updater is never reported as a cleanup failure.
func removeUpdaterBinary(path string) error {
	for attempt := 0; attempt < updaterRemoveAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(updaterRemoveDelay)
		}

		err := os.Remove(path)
		if err == nil || os.IsNotExist(err) {
			return nil
		}
		if !isFileLocked(err) {
			return err
		}
	}

	log.Debugf("updater binary %s is still locked, scheduling removal on next reboot", path)
	return scheduleDeleteOnReboot(path)
}

func isFileLocked(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}

func scheduleDeleteOnReboot(path string) error {
	from, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("convert path to UTF16: %w", err)
	}

	if err := windows.MoveFileEx(from, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); err != nil {
		return fmt.Errorf("schedule delete on reboot: %w", err)
	}
	return nil
}
