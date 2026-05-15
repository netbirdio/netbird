package ebpf

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	log "github.com/sirupsen/logrus"
)

const (
	mapKeyDNSIP   uint32 = 0
	mapKeyDNSPort uint32 = 1
)

func (tf *GeneralManager) LoadDNSFwd(ip netip.Addr, dnsPort int) error {
	log.Debugf("load eBPF DNS forwarder, watching addr: %s:53, redirect to port: %d", ip, dnsPort)
	tf.lock.Lock()
	defer tf.lock.Unlock()

	err := tf.loadXdp()
	if err != nil {
		return err
	}

	if !ip.Is4() {
		return fmt.Errorf("eBPF DNS forwarder only supports IPv4, got %s", ip)
	}
	ip4 := ip.As4()
	err = tf.bpfObjs.NbMapDnsIp.Put(mapKeyDNSIP, binary.BigEndian.Uint32(ip4[:]))
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

