package dns

// WGIface defines subset methods of interface required for manager
type WGIface interface {
	Name() string
	Address() iface.WGAddress
	IsUserspaceBind() bool
	GetFilter() iface.PacketFilter
	GetDevice() *iface.DeviceWrapper
	GetInterfaceGUIDString() (string, error)
}
