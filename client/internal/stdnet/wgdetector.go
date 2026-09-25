package stdnet

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// wgDetectorTTL bounds how long a cached answer is trusted. An interface rarely
// becomes, or stops being, a WireGuard device, and the window only has to be short
// enough that ICE does not keep gathering candidates on one that just appeared.
const wgDetectorTTL = 1 * time.Second

type wgDetectorEntry struct {
	isWireGuard bool
	expireAt    time.Time
}

// WGDetector answers whether an interface is a WireGuard device, remembering the
// answer for a short while.
//
// The question is asked once per interface for every ICE agent, and an agent is
// created per peer connection attempt, so on a large network the uncached form runs
// constantly. Answering it means opening a wgctrl client, which builds both a kernel
// and a userspace client and resolves the netlink family, and then a round trip that
// usually just reports the device does not exist.
//
// A detector is safe for concurrent use and is meant to be shared by every agent.
type WGDetector struct {
	ttl time.Duration
	// probe is replaced in tests; it is the call this type exists to avoid repeating.
	probe func(string) bool

	mu    sync.RWMutex
	cache map[string]wgDetectorEntry

	sf singleflight.Group
}

// NewWGDetector returns a detector with the default time to live.
func NewWGDetector() *WGDetector {
	return &WGDetector{
		ttl:   wgDetectorTTL,
		probe: probeWireGuard,
		cache: make(map[string]wgDetectorEntry),
	}
}

// IsWireGuard reports whether the named interface is a WireGuard device. An interface
// it cannot ask about is reported as not being one, which leaves it available to ICE
// exactly as an uncached probe would.
func (d *WGDetector) IsWireGuard(iFace string) bool {
	if d == nil {
		return probeWireGuard(iFace)
	}

	d.mu.RLock()
	entry, ok := d.cache[iFace]
	d.mu.RUnlock()
	if ok && time.Now().Before(entry.expireAt) {
		return entry.isWireGuard
	}

	result, _, _ := d.sf.Do(iFace, func() (interface{}, error) {
		isWireGuard := d.probe(iFace)

		d.mu.Lock()
		d.cache[iFace] = wgDetectorEntry{isWireGuard: isWireGuard, expireAt: time.Now().Add(d.ttl)}
		d.mu.Unlock()

		return isWireGuard, nil
	})
	return result.(bool)
}

func probeWireGuard(iFace string) bool {
	wg, err := wgctrl.New()
	if err != nil {
		log.Debugf("trying to create a wgctrl client failed with: %v", err)
		return false
	}
	defer func() {
		_ = wg.Close()
	}()

	_, err = wg.Device(iFace)
	return err == nil
}
