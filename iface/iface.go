// +build !linux

package iface

import (
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Saves tun device object - is it required?
var tunIface tun.Device

// Create Creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func Create(iface string, address string) error {
	var err error
	tunIface, err = tun.CreateTUN(iface, defaultMTU)
	if err != nil {
		return err
	}

	// We need to create a wireguard-go device and listen to configuration requests
	tunDevice := device.NewDevice(tunIface, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "[wiretrustee] "))
	err = tunDevice.Up()
	if err != nil {
		return err
	}
	uapi, err := getUAPI(iface)
	if err != nil {
		return err
	}

	go func() {
		for {
			uapiConn, err := uapi.Accept()
			if err != nil {
				log.Debugln(err)
				return
			}
			go tunDevice.IpcHandle(uapiConn)
		}
	}()

	log.Debugln("UAPI listener started")

	err = assignAddr(address, tunIface)
	if err != nil {
		return err
	}
	return nil
}
