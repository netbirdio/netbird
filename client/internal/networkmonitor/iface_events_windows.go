package networkmonitor

import (
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// A cable unplugged or Wi-Fi lost takes the interface's routes out of
// forwarding without a route notification, so the monitor also listens to
// interface changes. windows.NewCallback slots are never released, and
// checkChange runs again after every change, so one callback serves every
// subscription.
var (
	ifaceCallbackOnce sync.Once
	ifaceCallback     uintptr
	ifaceSubsMu       sync.Mutex
	ifaceSubs         = make(map[chan struct{}]struct{})
)

func notifyInterfaceSubscribers(_ uintptr, _ *windows.MibIpInterfaceRow, _ uint32) uintptr {
	ifaceSubsMu.Lock()
	defer ifaceSubsMu.Unlock()
	for ch := range ifaceSubs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	return 0
}

// subscribeInterfaceChanges signals on the returned channel whenever Windows
// reports an IP interface change. Bursts coalesce into one pending signal.
func subscribeInterfaceChanges() (<-chan struct{}, func(), error) {
	ifaceCallbackOnce.Do(func() {
		ifaceCallback = windows.NewCallback(notifyInterfaceSubscribers)
	})

	ch := make(chan struct{}, 1)
	ifaceSubsMu.Lock()
	ifaceSubs[ch] = struct{}{}
	ifaceSubsMu.Unlock()

	unsubscribe := func() {
		ifaceSubsMu.Lock()
		delete(ifaceSubs, ch)
		ifaceSubsMu.Unlock()
	}

	var handle windows.Handle
	if err := windows.NotifyIpInterfaceChange(windows.AF_UNSPEC, ifaceCallback, nil, false, &handle); err != nil {
		unsubscribe()
		return nil, nil, fmt.Errorf("NotifyIpInterfaceChange: %w", err)
	}

	stop := func() {
		if err := windows.CancelMibChangeNotify2(handle); err != nil {
			log.Debugf("Network monitor: failed to cancel interface notifications: %v", err)
		}
		unsubscribe()
	}
	return ch, stop, nil
}

// interfaceStates maps each interface index to whether it is operationally up.
type interfaceStates map[int]bool

func readInterfaceStates() (interfaceStates, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	states := make(interfaceStates, len(ifaces))
	for _, iface := range ifaces {
		states[iface.Index] = iface.Flags&net.FlagUp != 0
	}
	return states, nil
}

// changed returns an interface whose up state differs between the two
// snapshots, counting an interface that disappears while up as gone down.
func (before interfaceStates) changed(after interfaceStates) (int, bool) {
	for index, up := range after {
		if before[index] != up {
			return index, true
		}
	}
	for index, up := range before {
		if _, ok := after[index]; !ok && up {
			return index, true
		}
	}
	return 0, false
}
