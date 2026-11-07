//go:build !android && !ios

package systemops

import (
	"runtime"

	"github.com/netbirdio/netbird/client/internal/coexist"
)

// isOwnOrOtherOverlay reports whether an interface must not carry the
// installation's own exclusion routes: its own overlay adapter, and on Windows,
// where several installations can run, any other NetBird adapter.
func isOwnOrOtherOverlay(name, own string) bool {
	if name == own {
		return true
	}
	return runtime.GOOS == "windows" && coexist.IsOverlayInterface(name)
}
