package iface

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"net"
	"os"
	"runtime"
	"sync"
)

const (
	DefaultMTU    = 1280
	DefaultWgPort = 51820
)

// WGIface represents a interface instance
type WGIface struct {
	Name      string
	Port      int
	MTU       int
	Address   WGAddress
	Interface NetInterface
	mu        sync.Mutex
	Bind      *ICEBind
}

// WGAddress Wireguard parsed address
type WGAddress struct {
	IP      net.IP
	Network *net.IPNet
}

func (addr *WGAddress) String() string {
	maskSize, _ := addr.Network.Mask.Size()
	return fmt.Sprintf("%s/%d", addr.IP.String(), maskSize)
}

// NetInterface represents a generic network tunnel interface
type NetInterface interface {
	Close() error
}

// NewWGIFace Creates a new Wireguard interface instance
func NewWGIFace(iface string, address string, mtu int) (*WGIface, error) {
	wgIface := &WGIface{
		Name: iface,
		MTU:  mtu,
		mu:   sync.Mutex{},
	}

	wgAddress, err := parseAddress(address)
	if err != nil {
		return wgIface, err
	}

	wgIface.Address = wgAddress

	return wgIface, nil
}

// parseAddress parse a string ("1.2.3.4/24") address to WG Address
func parseAddress(address string) (WGAddress, error) {
	ip, network, err := net.ParseCIDR(address)
	if err != nil {
		return WGAddress{}, err
	}
	return WGAddress{
		IP:      ip,
		Network: network,
	}, nil
}

// Close closes the tunnel interface
func (w *WGIface) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	err := w.Interface.Close()
	if err != nil {
		return err
	}

	if runtime.GOOS == "darwin" {
		sockPath := "/var/run/wireguard/" + w.Name + ".sock"
		if _, statErr := os.Stat(sockPath); statErr == nil {
			statErr = os.Remove(sockPath)
			if statErr != nil {
				return statErr
			}
		}
	}

	return nil
}

func (w *WGIface) CreateNew(bind conn.Bind) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.createWithUserspaceNew(bind)
}

func (w *WGIface) createWithUserspaceNew(bind conn.Bind) error {
	tunIface, err := tun.CreateTUN(w.Name, w.MTU)
	if err != nil {
		return err
	}

	w.Interface = tunIface

	// We need to create a wireguard-go device and listen to configuration requests
	tunDevice := device.NewDevice(tunIface, bind, device.NewLogger(device.LogLevelSilent, "[wiretrustee] "))
	err = tunDevice.Up()
	if err != nil {
		return err
	}
	uapi, err := getUAPI(w.Name)
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
