package forwarder

import (
	_ "embed"
	"encoding/binary"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

const (
	mapKeyDNSIP   uint32 = 0
	mapKeyDNSPort uint32 = 1
)

// libbpf-dev, libc6-dev-i386-amd64-cross
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 bpf src/port_fwd.c -- -I /usr/x86_64-linux-gnu/include
type TrafficForwarder struct {
	link      link.Link
	iFaceName string
}

func NewTrafficForwarder(iFace string) *TrafficForwarder {
	return &TrafficForwarder{
		iFaceName: iFace,
	}
}

func (tf *TrafficForwarder) Start(ip string, dnsPort int) error {
	log.Debugf("start DNS port forwarder")
	// it required for Docker
	err := rlimit.RemoveMemlock()
	if err != nil {
		return err
	}

	iFace, err := net.InterfaceByName(tf.iFaceName)
	if err != nil {
		return err
	}

	// load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	err = loadBpfObjects(&objs, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = objs.Close()
	}()

	err = objs.XdpPortMap.Put(mapKeyDNSIP, tf.ip2int(ip))
	if err != nil {
		return err
	}

	err = objs.XdpPortMap.Put(mapKeyDNSPort, uint16(dnsPort))
	if err != nil {
		return err
	}

	defer func() {
		_ = objs.XdpPortMap.Close()
	}()

	tf.link, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDnsPortFwd,
		Interface: iFace.Index,
	})
	return err
}

func (tf *TrafficForwarder) Free() error {
	if tf.link == nil {
		return nil
	}

	err := tf.link.Close()
	tf.link = nil
	return err
}

func (tf *TrafficForwarder) ip2int(ipString string) uint32 {
	ip := net.ParseIP(ipString)
	return binary.BigEndian.Uint32(ip.To4())
}
