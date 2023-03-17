package iface

// NetInterface represents a generic network tunnel interface
type NetInterface interface {
	Close() error
}
