package iface

import (
	//log "github.com/sirupsen/logrus"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"net"
	"strconv"
)

const (
	defaultMTU     = 1280
	interfaceLimit = 10 // can be higher. Need to check different OS limits
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
	tunDevice := device.NewDevice(tunIface, device.NewLogger(device.LogLevelSilent, "[wiretrustee] "))
	tunDevice.Up()
	tunSock, err := ipc.UAPIOpen(iface)
	if err != nil {
		return err
	}
	uapi, err := ipc.UAPIListen(iface, tunSock)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := uapi.Accept()
			if err != nil {
				log.Debugln(err)
				return
			}
			go tunDevice.IpcHandle(conn)
		}
	}()

	log.Debugln("UAPI listener started")

	err = assignAddr(iface, address)
	if err != nil {
		return err
	}
	return nil
}

// Deletes an existing Wireguard interface
func Delete() error {
	return tunIface.Close()
}

// GetIfaceName loops through the OS' interfaceLimit and returns the first available interface name based on
// interface prefixes and index
func GetIfaceName() (string, error) {
	for i := 0; i < interfaceLimit; i++ {
		_, err := net.InterfaceByName(interfacePrefix + strconv.Itoa(i))
		if err != nil {
			if err.Error() != "no such network interface" {
				return interfacePrefix + strconv.Itoa(i), nil
			}
		}
	}
	return "none", errors.New(fmt.Sprintf("Couldn't find an available interface index within the limit of: %d", interfaceLimit))
}
