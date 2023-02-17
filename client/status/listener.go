package status

// Listener is a callback type about the NetBird service state
type Listener interface {
	OnConnected()
	OnDisconnected()
	OnConnecting()
}
