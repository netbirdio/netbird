//go:build linux || darwin

package tun

import (
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

type Device struct {
	Name    string
	IP      string
	PConn   net.PacketConn
	DstAddr net.Addr

	iFace *water.Interface
	proxy *Proxy
}

func (d *Device) Up() error {
	cfg := water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: d.Name,
		},
	}
	iFace, err := water.New(cfg)
	if err != nil {
		return err
	}
	d.iFace = iFace

	err = d.assignIP()
	if err != nil {
		return err
	}

	err = d.bringUp()
	if err != nil {
		return err
	}

	d.proxy = &Proxy{
		Device:  d,
		PConn:   d.PConn,
		DstAddr: d.DstAddr,
	}
	d.proxy.Start()
	return nil
}

func (d *Device) Close() error {
	if d.proxy != nil {
		d.proxy.Close()
	}
	if d.iFace != nil {
		return d.iFace.Close()
	}
	return nil
}

func (d *Device) Read(b []byte) (int, error) {
	return d.iFace.Read(b)
}

func (d *Device) Write(b []byte) (int, error) {
	return d.iFace.Write(b)
}

func (d *Device) assignIP() error {
	iface, err := netlink.LinkByName(d.Name)
	if err != nil {
		log.Errorf("failed to get TUN device: %v", err)
		return err
	}

	ip := net.IPNet{
		IP:   net.ParseIP(d.IP),
		Mask: net.CIDRMask(24, 32),
	}

	addr := &netlink.Addr{
		IPNet: &ip,
	}
	err = netlink.AddrAdd(iface, addr)
	if err != nil {
		log.Errorf("failed to add IP address: %v", err)
		return err
	}
	return nil
}

func (d *Device) bringUp() error {
	iface, err := netlink.LinkByName(d.Name)
	if err != nil {
		log.Errorf("failed to get device: %v", err)
		return err
	}

	// Bring the interface up
	err = netlink.LinkSetUp(iface)
	if err != nil {
		log.Errorf("failed to set device up: %v", err)
		return err
	}
	return nil
}
