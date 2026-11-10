//go:build darwin && !ios

package server

import (
	"context"
	"net"
	"os"

	log "github.com/sirupsen/logrus"
)

// ListenAgentSocket binds the Unix-domain socket the vnc-agent serves on,
// replacing a stale socket file left at the path, and restricts it to the
// owning user.
func ListenAgentSocket(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Debugf("remove stale socket %s: %v", path, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		log.Debugf("chmod %s: %v", path, err)
	}
	return ln, nil
}

func dialAgent(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", addr)
}
