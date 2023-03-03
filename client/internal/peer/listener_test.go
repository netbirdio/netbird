package peer

type MocListener struct {
	state string
}

func newMockListener() *MocListener {
	return &MocListener{}
}

func (m *MocListener) OnConnected() {
	m.state = "connected"

}

func (m *MocListener) OnDisconnected() {
	m.state = "disconnected"
}

func (m *MocListener) OnConnecting() {
	m.state = "connecting"
}
