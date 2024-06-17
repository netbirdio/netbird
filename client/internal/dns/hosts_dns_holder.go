package dns

import (
	"fmt"
	"net/netip"
	"sync"

	log "github.com/sirupsen/logrus"
)

type hostsDNSHolder struct {
	unprotectedDNSList map[string]struct{}
	mutex              sync.RWMutex
}

func newHostsDNSHolder() *hostsDNSHolder {
	return &hostsDNSHolder{
		unprotectedDNSList: make(map[string]struct{}),
	}
}

func (h *hostsDNSHolder) set(list []string) {
	h.mutex.Lock()
	h.unprotectedDNSList = make(map[string]struct{})
	for _, dns := range list {
		dnsAddr, err := h.normalizeAddress(dns)
		if err != nil {
			continue
		}
		h.unprotectedDNSList[dnsAddr] = struct{}{}
	}
	h.mutex.Unlock()
}

func (h *hostsDNSHolder) get() map[string]struct{} {
	h.mutex.RLock()
	l := h.unprotectedDNSList
	h.mutex.RUnlock()
	return l
}

//nolint:unused
func (h *hostsDNSHolder) isContain(upstream string) bool {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	_, ok := h.unprotectedDNSList[upstream]
	return ok
}

func (h *hostsDNSHolder) normalizeAddress(addr string) (string, error) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		log.Errorf("invalid upstream IP address: %s, error: %s", addr, err)
		return "", err
	}

	if a.Is4() {
		return fmt.Sprintf("%s:53", addr), nil
	} else {
		return fmt.Sprintf("[%s]:53", addr), nil
	}
}
