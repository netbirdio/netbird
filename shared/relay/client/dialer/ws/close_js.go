//go:build js

package ws

import (
	"github.com/coder/websocket"
	log "github.com/sirupsen/logrus"
)

// closeConn closes the browser WebSocket without blocking the caller.
//
// The browser close API only accepts codes 1000 and 3000-4999, so CloseNow's
// 1001 (going away) throws an InvalidAccessError. Close with a valid code
// waits for the browser close event before returning, which can park the
// calling goroutine (the relay teardown path holds its mutexes while closing)
// until the close handshake finishes. Run the close in the background and
// report success; a teardown close error is not actionable.
func (c *Conn) closeConn() error {
	go func() {
		if err := c.Conn.Close(websocket.StatusNormalClosure, ""); err != nil {
			log.Debugf("failed to close relay websocket: %v", err)
		}
	}()
	return nil
}
