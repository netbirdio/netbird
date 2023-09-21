package netbird

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

// // CloseLog closes the log file.
// func CloseLog() {
// 	if logFile != nil {
// 		logFile.Close()
// 	}
// }
//
// // Log writes a message to the log file.
// func Log(message string) {
// 	if logFile != nil {
// 		ts := time.Now().Format(time.RFC3339)
// 		fmt.Fprintf(logFile, "%s: %s\n", ts, message)
// 	}
// }
