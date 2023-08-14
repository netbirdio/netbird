package ebpf

import (
	_ "embed"
	"net"
	"sync"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

const (
	mapKeyFeatures uint32 = 0

	featureFlagWGProxy      = 0b00000001
	featureFlagDnsForwarder = 0b00000010
)

var (
	singleton     *Manager
	singletonLock = &sync.Mutex{}
)

// libbpf-dev, libc6-dev-i386-amd64-cross

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 bpf src/prog.c -- -I /usr/x86_64-linux-gnu/include
type Manager struct {
	lock         sync.Mutex
	link         link.Link
	featureFlags uint16
	bpfObjs      bpfObjects
}

// GetEbpfManagerInstance return a static eBpf Manager instance
func GetEbpfManagerInstance() *Manager {
	singletonLock.Lock()
	defer singletonLock.Unlock()
	if singleton != nil {
		return singleton
	}
	singleton = &Manager{}
	return singleton
}

func (tf *Manager) setFeatureFlag(feature uint16) {
	tf.featureFlags = tf.featureFlags | feature
}

func (tf *Manager) loadXdp() error {
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
	return err
}

func (tf *Manager) unsetFeatureFlag(feature uint16) error {
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

func (tf *Manager) close() error {
	log.Debugf("detach ebpf program ")
	err := tf.bpfObjs.Close()
	if err != nil {
		log.Warnf("failed to close eBpf objects: %s", err)
	}

	err = tf.link.Close()
	tf.link = nil
	return err
}
