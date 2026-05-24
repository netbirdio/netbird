//go:build darwin && !ios

package cmd

import "os"

// currentUIDForTest exposes os.Getuid for the darwin dropprivs tests
// without leaking an os import into the test file itself.
func currentUIDForTest() uint32 {
	return uint32(os.Getuid())
}
