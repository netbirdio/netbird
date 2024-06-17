package ebpf

import (
	_ "embed"
	"net"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/ebpf/manager"
)

const (
	mapKeyFeatures uint32 = 0

	featureFlagWGProxy      = 0b00000001
	featureFlagDnsForwarder = 0b00000010
)

var (
	singleton     manager.Manager
	singletonLock = &sync.Mutex{}
)

// required packages libbpf-dev, libc6-dev-i386-amd64-cross

// GeneralManager is used to load multiple eBPF programs with a custom check (if then) done in prog.c
// The manager simply adds a feature (byte) of each program to a map that is shared between the userspace and kernel.
// When packet arrives, the C code checks for each feature (if it is set) and executes each enabled program (e.g., dns_fwd.c and wg_proxy.c).
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 bpf src/prog.c -- -I /usr/x86_64-linux-gnu/include
type GeneralManager struct {
	lock         sync.Mutex
	link         link.Link
	featureFlags uint16
	bpfObjs      bpfObjects
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

func (tf *GeneralManager) setFeatureFlag(feature uint16) {
	tf.featureFlags |= feature
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

	iFace, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}

	// load pre-compiled programs into the kernel.
	err = loadBpfObjects(&tf.bpfObjs, nil)
	if err != nil {
		return err
	}

	tf.link, err = link.AttachXDP(link.XDPOptions{
		Program:   tf.bpfObjs.NbXdpProg,
		Interface: iFace.Index,
	})

	if err != nil {
		_ = tf.bpfObjs.Close()
		tf.link = nil
		return err
	}
	return nil
}

func (tf *GeneralManager) unsetFeatureFlag(feature uint16) error {
	tf.lock.Lock()
	defer tf.lock.Unlock()
	tf.featureFlags &^= feature

	if tf.link == nil {
		return nil
	}

	if tf.featureFlags == 0 {
		return tf.close()
	}

	return tf.bpfObjs.NbFeatures.Put(mapKeyFeatures, tf.featureFlags)
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
