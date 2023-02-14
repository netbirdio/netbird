package iface

type tunDevice struct {
	wGConfigurer wGConfigurer
}

func newTunDevice(wGConfigurer wGConfigurer) tunDevice {
	return tunDevice{
		wGConfigurer: wGConfigurer,
	}
}

func (t *tunDevice) deviceName() string {
	return t.wGConfigurer.deviceName
}

func (t *tunDevice) create() error {
	return nil
}

func (t *tunDevice) updateAddr(address WGAddress) error {
	return t.wGConfigurer.updateAddress(address)
}

func (t *tunDevice) wgAddress() WGAddress {
	return t.wGConfigurer.address
}

func (t *tunDevice) close() error {
	t.wGConfigurer.close()
	return nil
}
