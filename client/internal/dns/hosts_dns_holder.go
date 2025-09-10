package dns

import (
	"net/netip"
	"sync"
)

type hostsDNSHolder struct {
	unprotectedDNSList map[netip.AddrPort]struct{}
	mutex              sync.RWMutex
}

func newHostsDNSHolder() *hostsDNSHolder {
	return &hostsDNSHolder{
		unprotectedDNSList: make(map[netip.AddrPort]struct{}),
	}
}

func (h *hostsDNSHolder) set(list []netip.AddrPort) {
	h.mutex.Lock()
	h.unprotectedDNSList = make(map[netip.AddrPort]struct{})
	for _, addrPort := range list {
		h.unprotectedDNSList[addrPort] = struct{}{}
	}
	h.mutex.Unlock()
}

func (h *hostsDNSHolder) get() map[netip.AddrPort]struct{} {
	h.mutex.RLock()
	l := h.unprotectedDNSList
	h.mutex.RUnlock()
	return l
}

//nolint:unused
func (h *hostsDNSHolder) contains(upstream netip.AddrPort) bool {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	_, ok := h.unprotectedDNSList[upstream]
	return ok
}
