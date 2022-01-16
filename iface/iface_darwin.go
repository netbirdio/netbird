package iface

import (
	log "github.com/sirupsen/logrus"
	"os"
	"os/exec"
)

// Create Creates a new Wireguard interface, sets a given IP and brings it up.
func Create(iface string, address string) (WGIface, error) {
	return CreateWithUserspace(iface, address)
}

// assignAddr Adds IP address to the tunnel interface and network route based on the range provided
func (w *WGIface) assignAddr() error {
	//mask,_ := w.Address.Network.Mask.Size()
	//
	//address := fmt.Sprintf("%s/%d",w.Address.IP.String() , mask)

	cmd := exec.Command("ifconfig", w.Name, "inet", w.Address.IP.String(), w.Address.IP.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Infof("adding addreess command \"%v\" failed with output %s and error: ", cmd.String(), out)
		return err
	}

	routeCmd := exec.Command("route", "add", "-net", w.Address.Network.String(), "-interface", w.Name)
	if out, err := routeCmd.CombinedOutput(); err != nil {
		log.Printf("adding route command \"%v\" failed with output %s and error: ", routeCmd.String(), out)
		return err
	}

	return nil
}

// Closes the tunnel interface
func (w *WGIface) Close() error {

	err := w.Interface.Close()
	if err != nil {
		return err
	}

	sockPath := "/var/run/wireguard/" + w.Name + ".sock"
	if _, statErr := os.Stat(sockPath); statErr == nil {
		statErr = os.Remove(sockPath)
		if statErr != nil {
			return statErr
		}
	}
	return nil
}
