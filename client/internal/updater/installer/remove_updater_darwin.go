package installer

import "os"

// removeUpdaterBinary deletes the updater copy left in the temp dir. On darwin a
// running binary can be unlinked, so no retry is needed.
func removeUpdaterBinary(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
