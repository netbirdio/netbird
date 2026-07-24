//go:build windows

package ipcauth

// NewDefaultGroupResolver returns nil on Windows: group authorization uses the
// group SIDs carried in the client token (see the Windows transport
// credentials).
func NewDefaultGroupResolver() GroupResolver {
	return nil
}
