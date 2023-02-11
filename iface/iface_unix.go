//go:build linux || darwin
// +build linux darwin

package iface

import (
	"net"
	"os"

	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

// GetInterfaceGUIDString returns an interface GUID. This is useful on Windows only
func (w *WGIface) GetInterfaceGUIDString() (string, error) {
	return "", nil
}

// Close closes the tunnel interface
func (w *WGIface) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.Interface == nil {
		return nil
	}
	err := w.Interface.Close()
	if err != nil {
		return err
	}

	sockPath := "/var/run/wireguard/" + w.name + ".sock"
	if _, statErr := os.Stat(sockPath); statErr == nil {
		statErr = os.Remove(sockPath)
		if statErr != nil {
			return statErr
		}
	}

	return nil
}

// createWithUserspace Creates a new Wireguard interface, using wireguard-go userspace implementation
func (w *WGIface) createWithUserspace() error {

	tunIface, err := tun.CreateTUN(w.name, w.MTU)
	if err != nil {
		return err
	}

	w.Interface = tunIface

	// We need to create a wireguard-go device and listen to configuration requests
	tunDevice := device.NewDevice(tunIface, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "[wiretrustee] "))
	err = tunDevice.Up()
	if err != nil {
		return err
	}
	uapi, err := getUAPI(w.name)
	if err != nil {
		return err
	}

	go func() {
		for {
			uapiConn, uapiErr := uapi.Accept()
			if uapiErr != nil {
				log.Traceln("uapi Accept failed with error: ", uapiErr)
				continue
			}
			go tunDevice.IpcHandle(uapiConn)
		}
	}()

	log.Debugln("UAPI listener started")

	err = w.assignAddr()
	if err != nil {
		return err
	}
	return nil
}

// getUAPI returns a Listener
func getUAPI(iface string) (net.Listener, error) {
	tunSock, err := ipc.UAPIOpen(iface)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(iface, tunSock)
}
