package installer

import (
	"errors"
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
// while the still-exiting updater process holds its image. A binary that stays
// locked for the whole window is left in place and reported at info level: the
// next update overwrites it, so it is not worth failing cleanup over.
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

	log.Infof("updater binary %s is still locked, leaving it for the next update to overwrite", path)
	return nil
}

func isFileLocked(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}
