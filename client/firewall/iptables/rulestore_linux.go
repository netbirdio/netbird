package iptables

type ipList struct {
	ips map[string]struct{}
}

func newIpList(ip string) ipList {
	ips := make(map[string]struct{})
	ips[ip] = struct{}{}

	return ipList{
		ips: ips,
	}
}

func (s *ipList) addIP(ip string) {
	s.ips[ip] = struct{}{}
}

type ipsetStore struct {
	ipsets map[string]ipList // ipsetName -> ruleset
}

func newIpsetStore() *ipsetStore {
	return &ipsetStore{
		ipsets: make(map[string]ipList),
	}
}

func (s *ipsetStore) ipset(ipsetName string) (ipList, bool) {
	r, ok := s.ipsets[ipsetName]
	return r, ok
}

func (s *ipsetStore) addIpList(ipsetName string, list ipList) {
	s.ipsets[ipsetName] = list
}

func (s *ipsetStore) deleteIpset(ipsetName string) {
	s.ipsets[ipsetName] = ipList{}
	delete(s.ipsets, ipsetName)
}

func (s *ipsetStore) ipsetNames() []string {
	names := make([]string, 0, len(s.ipsets))
	for name := range s.ipsets {
		names = append(names, name)
	}
	return names
}
