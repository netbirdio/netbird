package net

// init configures the net.ListenerConfig Control function to set the fwmark on the socket
func (l *ListenerConfig) init() {
	l.ListenConfig.Control = ControlProtectSocket
}
