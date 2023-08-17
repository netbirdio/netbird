//go:build !android

package ebpf

import (
	"encoding/binary"
	"net"

	log "github.com/sirupsen/logrus"
)

const (
	mapKeyFakeIP  uint32 = 0
	mapKeyDNSIP   uint32 = 1
	mapKeyDNSPort uint32 = 2
)

func (tf *GeneralManager) LoadDNSFwd(fakeIp, dnsIp string, dnsPort int) error {
	log.Debugf("load ebpf DNS forwarder: address: %s:%d", dnsIp, dnsPort)
	tf.lock.Lock()
	defer tf.lock.Unlock()

	err := tf.loadXdp()
	if err != nil {
		return err
	}

	err = tf.bpfObjs.NbMapDnsIp.Put(mapKeyFakeIP, ip2int(fakeIp))
	if err != nil {
		return err
	}

	err = tf.bpfObjs.NbMapDnsIp.Put(mapKeyDNSIP, ip2int(dnsIp))
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
