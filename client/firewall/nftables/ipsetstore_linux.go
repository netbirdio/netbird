package nftables

import (
	"net"
)

type ipsetStore struct {
	ipsetReference map[string]int
	ipsets         map[string]map[string]struct{} // ipsetName -> list of ips
}

func newIpsetStore() *ipsetStore {
	return &ipsetStore{
		ipsetReference: make(map[string]int),
		ipsets:         make(map[string]map[string]struct{}),
	}
}

func (s *ipsetStore) ips(ipsetName string) (map[string]struct{}, bool) {
	r, ok := s.ipsets[ipsetName]
	return r, ok
}

func (s *ipsetStore) newIpset(ipsetName string) map[string]struct{} {
	s.ipsetReference[ipsetName] = 0
	ipList := make(map[string]struct{})
	s.ipsets[ipsetName] = ipList
	return ipList
}

func (s *ipsetStore) deleteIpset(ipsetName string) {
	delete(s.ipsetReference, ipsetName)
	delete(s.ipsets, ipsetName)
}

func (s *ipsetStore) DeleteIpFromSet(ipsetName string, ip net.IP) {
	ipList, ok := s.ipsets[ipsetName]
	if !ok {
		return
	}
	delete(ipList, ip.String())
}

func (s *ipsetStore) AddIpToSet(ipsetName string, ip net.IP) {
	ipList, ok := s.ipsets[ipsetName]
	if !ok {
		return
	}
	ipList[ip.String()] = struct{}{}
}

func (s *ipsetStore) IsIpInSet(ipsetName string, ip net.IP) bool {
	ipList, ok := s.ipsets[ipsetName]
	if !ok {
		return false
	}
	_, ok = ipList[ip.String()]
	return ok
}

func (s *ipsetStore) AddReferenceToIpset(ipsetName string) {
	s.ipsetReference[ipsetName]++
}

func (s *ipsetStore) DeleteReferenceFromIpSet(ipsetName string) {
	r, ok := s.ipsetReference[ipsetName]
	if !ok {
		return
	}
	if r == 0 {
		return
	}
	s.ipsetReference[ipsetName]--
}

func (s *ipsetStore) HasReferenceToSet(ipsetName string) bool {
	if _, ok := s.ipsetReference[ipsetName]; !ok {
		return false
	}
	if s.ipsetReference[ipsetName] == 0 {
		return false
	}

	return true
}
