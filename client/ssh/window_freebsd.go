//go:build freebsd

package ssh

import (
	"os"
)

func setWinSize(file *os.File, width, height int) {
}
