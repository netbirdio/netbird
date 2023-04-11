package iface

// TunAdapter is an interface for create tun device from externel service
type TunAdapter interface {
	ConfigureInterface(address string, mtu int, routes string) (int, error)
	UpdateAddr(address string) error
}
