//go:build !unix

package harness

import "io/fs"

// fileOwnerUID reports no owner where files carry no owner uid (Windows uses
// ACLs and has no effective uid), so the ownership check is skipped there.
func fileOwnerUID(fs.FileInfo) (uint32, bool) {
	return 0, false
}
