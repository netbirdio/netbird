package ebpf

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/netbirdio/netbird/relay/ebpf/manager"
)

var (
	singleton     manager.Manager
	singletonLock = &sync.Mutex{}
)

// required packages libbpf-dev, libc6-dev-i386-amd64-cross

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 bpf src/prog.c -- -I /usr/x86_64-linux-gnu/include
type GeneralManager struct {
	lock    sync.Mutex
	link    link.Link
	bpfObjs bpfObjects
	iface   *net.Interface
}

// GetEbpfManagerInstance return a static eBpf Manager instance
func GetEbpfManagerInstance() manager.Manager {
	singletonLock.Lock()
	defer singletonLock.Unlock()
	if singleton != nil {
		return singleton
	}
	singleton = &GeneralManager{}
	return singleton
}

func (tf *GeneralManager) LoadWgProxy() error {
	log.Debugf("load ebpf WG proxy")
	tf.lock.Lock()
	defer tf.lock.Unlock()

	err := tf.loadXdp()
	if err != nil {
		return err
	}

	return nil
}

func (tf *GeneralManager) loadXdp() error {
	if tf.link != nil {
		return nil
	}
	// it required for Docker
	err := rlimit.RemoveMemlock()
	if err != nil {
		return err
	}

	ifaceName := os.Getenv("NB_EBPF_IFACE")
	if ifaceName == "" {
		ifaceName = "enp7s0"
	}
	iFace, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return err
	}
	tf.iface = iFace

	// load pre-compiled programs into the kernel.
	err = loadBpfObjects(&tf.bpfObjs, nil)
	if err != nil {
		return err
	}

	tf.link, err = link.AttachXDP(link.XDPOptions{
		Program:   tf.bpfObjs.RelayXdpProg,
		Interface: iFace.Index,
	})

	if err != nil {
		_ = tf.bpfObjs.Close()
		tf.link = nil
		return err
	}

	return nil
}

func (tf *GeneralManager) AddPeer(channelID, dstID uint16, dstAddr netip.AddrPort) error {
	tf.lock.Lock()
	defer tf.lock.Unlock()
	if tf.bpfObjs.PeersMap == nil {
		return fmt.Errorf("peers_map not loaded")
	}

	// Convert netip.Addr to net.IP for To4() method
	ip := net.IP(dstAddr.Addr().AsSlice())
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 is supported")
	}

	// Convert IP to uint32 in little endian
	ipUint := binary.LittleEndian.Uint32(ip4)

	// Convert port to little endian uint16
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, dstAddr.Port())
	portUint := binary.LittleEndian.Uint16(portBytes)

	dstMAC, err := tf.resolveNeighborMAC(dstAddr.Addr())
	if err != nil {
		return fmt.Errorf("resolve dst mac for %s: %w", dstAddr.Addr(), err)
	}

	value := PeerValue{
		DestIP:   ipUint,
		DestPort: portUint,
		DstID:    dstID,
	}
	copy(value.DstMAC[:], dstMAC)
	copy(value.SrcMAC[:], tf.iface.HardwareAddr)

	log.Infof("adding peer to ebpf map channelID=%d dstID=%d dstAddr=%s dstMAC=%s srcMAC=%s", channelID, dstID, dstAddr.String(), dstMAC, tf.iface.HardwareAddr)
	key := channelID
	return tf.bpfObjs.PeersMap.Put(key, value)
}

func (tf *GeneralManager) resolveNeighborMAC(addr netip.Addr) (net.HardwareAddr, error) {
	target := net.IP(addr.AsSlice())
	neighs, err := netlink.NeighList(tf.iface.Index, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	for _, n := range neighs {
		if n.IP.Equal(target) && n.HardwareAddr != nil {
			return n.HardwareAddr, nil
		}
	}
	return nil, fmt.Errorf("no neighbor entry for %s on %s", target, tf.iface.Name)
}

func (tf *GeneralManager) close() error {
	log.Debugf("detach ebpf program ")
	err := tf.bpfObjs.Close()
	if err != nil {
		log.Warnf("failed to close eBpf objects: %s", err)
	}

	err = tf.link.Close()
	tf.link = nil
	return err
}
