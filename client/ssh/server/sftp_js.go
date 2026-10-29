//go:build js

package server

import (
	"os/user"
)

// parseUserCredentials is not supported on JS/WASM
func (s *Server) parseUserCredentials(_ *user.User) (uint32, uint32, []uint32, error) {
	return 0, 0, nil, errNotSupported
}
