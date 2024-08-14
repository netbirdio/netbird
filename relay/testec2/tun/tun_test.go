package tun

import "testing"

func TestDevice_assignIP(t *testing.T) {
	d := Device{
		Name: "mytun0",
		IP:   "10.0.0.1",
	}
	err := d.Up()
	if err != nil {
		t.Fatalf("failed to bring up device: %v", err)
	}
	defer d.Close()
	select {}
}
