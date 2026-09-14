//go:build !windows && !js

package filedrop

import (
	"fmt"
	"os"
	"syscall"
)

func chownToDirOwner(path, dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat destination dir: %w", err)
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if os.Geteuid() != 0 || int(stat.Uid) == os.Geteuid() {
		return nil
	}

	if err := os.Chown(path, int(stat.Uid), int(stat.Gid)); err != nil {
		return fmt.Errorf("chown delivered file: %w", err)
	}
	return nil
}
