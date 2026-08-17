package ebpf

import (
	_ "embed"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/ebpf/manager"
)

const (
	xdpProgName = "nb_xdp_prog"

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

	// lo has no native XDP, so the program runs in generic mode. Unless it
	// declares multi-buffer support the kernel must linearize every non-linear
	// skb before running it. Loopback packets are up to 64 KB, so that is a
	// contiguous GFP_ATOMIC allocation per packet, and when it fails the packet
	// is dropped before the program runs, stalling local TCP connections.
	// Multi-buffer XDP in generic mode requires kernel 6.3, so fall back to a
	// plain attach when the kernel rejects it.
	err = tf.attachXdp(iFace.Index, true)
	if err == nil {
		return nil
	}
	log.Debugf("failed to attach multi-buffer xdp program, retrying without it: %s", err)

	return tf.attachXdp(iFace.Index, false)
}

func (tf *GeneralManager) attachXdp(iFaceIndex int, multiBuffer bool) error {
	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("load bpf spec: %w", err)
	}

	if multiBuffer {
		prog, ok := spec.Programs[xdpProgName]
		if !ok {
			return fmt.Errorf("program %s not found in bpf spec", xdpProgName)
		}
		prog.Flags |= unix.BPF_F_XDP_HAS_FRAGS
	}

	if err := spec.LoadAndAssign(&tf.bpfObjs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}

	tf.link, err = link.AttachXDP(link.XDPOptions{
		Program:   tf.bpfObjs.NbXdpProg,
		Interface: iFaceIndex,
	})
	if err != nil {
		_ = tf.bpfObjs.Close()
		tf.link = nil
		return fmt.Errorf("attach xdp: %w", err)
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
