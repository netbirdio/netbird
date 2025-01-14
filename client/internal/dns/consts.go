//go:build !android

package dns

import (
	"github.com/netbirdio/netbird/client/configs"
	"os"
	"path/filepath"
)

var fileUncleanShutdownResolvConfLocation string

func init() {
	fileUncleanShutdownResolvConfLocation = os.Getenv("NB_UNCLEAN_SHUTDOWN_RESOLV_FILE")
	if fileUncleanShutdownResolvConfLocation == "" {
		fileUncleanShutdownResolvConfLocation = filepath.Join(configs.StateDir, "resolv.conf")
	}
}
