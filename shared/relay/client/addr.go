package client

type RelayAddr struct {
	addr string
}

func (a RelayAddr) Network() string {
	return "relay"
}

func (a RelayAddr) String() string {
	return a.addr
}
