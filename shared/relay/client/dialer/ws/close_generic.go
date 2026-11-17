//go:build !js

package ws

// closeConn closes the underlying WebSocket immediately, skipping the close
// handshake.
func (c *Conn) closeConn() error {
	return c.Conn.CloseNow()
}
