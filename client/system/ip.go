package system

import (
	"net"

	log "github.com/sirupsen/logrus"
)

func localAddresses() (string, string) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		log.Errorf("failed to check ip: %s", err)
		return "", ""
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Errorf("failed to list interfaces: %s", err)
		return "", ""
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			log.Errorf("failed to list addresses: %s", err)
			continue
		}

		for _, addr := range addrs {
			cidr, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}

			if localAddr.IP.String() == cidr.String() {
				return addr.String(), i.HardwareAddr.String()
			}
		}
	}
	return "", ""
}
