package iface

type WGAdapter interface {
	ConfigureInterface(address string, mtu int) (int, error)
	UpdateAddr(address string) error
}
