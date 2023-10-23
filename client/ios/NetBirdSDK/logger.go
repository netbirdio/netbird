package NetBirdSDK

import (
	"os"

	"github.com/netbirdio/netbird/util"
)

var logFile *os.File

// InitializeLog initializes the log file.
func InitializeLog(logLevel string, filePath string) error {
	var err error
	err = util.InitLog(logLevel, filePath)
	return err
}
