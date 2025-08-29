package ebpf

import (
	"encoding/binary"
	"net"

	log "github.com/sirupsen/logrus"
)

const (
	mapKeyDNSIP   uint32 = 0
	mapKeyDNSPort uint32 = 1
)

func (tf *GeneralManager) LoadDNSFwd(ip string, dnsPort int) error {
	log.Debugf("load eBPF DNS forwarder, watching addr: %s:53, redirect to port: %d", ip, dnsPort)
	tf.lock.Lock()
	defer tf.lock.Unlock()

	err := tf.loadXdp()
	if err != nil {
		return err
	}

	err = tf.bpfObjs.NbMapDnsIp.Put(mapKeyDNSIP, ip2int(ip))
	if err != nil {
		return err
	}

	err = tf.bpfObjs.NbMapDnsPort.Put(mapKeyDNSPort, uint16(dnsPort))
	if err != nil {
		return err
	}

	tf.setFeatureFlag(featureFlagDnsForwarder)
	err = tf.bpfObjs.NbFeatures.Put(mapKeyFeatures, tf.featureFlags)
	if err != nil {
		return err
	}
	return nil
}

func (tf *GeneralManager) FreeDNSFwd() error {
	log.Debugf("free ebpf DNS forwarder")
	return tf.unsetFeatureFlag(featureFlagDnsForwarder)
}

func ip2int(ipString string) uint32 {
	ip := net.ParseIP(ipString)
	return binary.BigEndian.Uint32(ip.To4())
}
