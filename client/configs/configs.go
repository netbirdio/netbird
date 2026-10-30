package configs

import (
	"github.com/netbirdio/netbird/client/internal/instance"
)

// UILogFile is the file name the desktop UI writes its log to. It is defined
// here so the UI (writer), the daemon's RegisterUILog validation, and the debug
// bundle collector all share one definition.
const UILogFile = "gui-client.log"

// StateDir is the daemon's state directory, from the identity package.
var StateDir string

func init() {
	StateDir = instance.Current().StateDir()
	instance.OnSetCurrent(func(inst instance.Instance) {
		StateDir = inst.StateDir()
	})
}
