package iface

// TunAdapter is an interface for create tun device from external service
type TunAdapter interface {
	ConfigureInterface(address string, mtu int, dns string, searchDomains string, routes string) (int, error)
	UpdateAddr(address string) error
	ProtectSocket(fd int32) bool
}
