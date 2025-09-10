package net

func (d *Dialer) init() {
	d.Dialer.Control = ControlProtectSocket
}
