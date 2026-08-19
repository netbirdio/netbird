package iptables

import (
	"encoding/json"
	"maps"
)

type ipList struct {
	ips map[string]struct{}
}

func newIpList(ip string) *ipList {
	ips := make(map[string]struct{})
	ips[ip] = struct{}{}

	return &ipList{
		ips: ips,
	}
}

func (s *ipList) addIP(ip string) {
	s.ips[ip] = struct{}{}
}

// clone returns a deep copy of the ipList with its own ips map.
func (s *ipList) clone() *ipList {
	if s == nil {
		return nil
	}
	return &ipList{ips: maps.Clone(s.ips)}
}

// MarshalJSON implements json.Marshaler
func (s *ipList) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		IPs map[string]struct{} `json:"ips"`
	}{
		IPs: s.ips,
	})
}

// UnmarshalJSON implements json.Unmarshaler
func (s *ipList) UnmarshalJSON(data []byte) error {
	temp := struct {
		IPs map[string]struct{} `json:"ips"`
	}{}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	s.ips = temp.IPs

	if temp.IPs == nil {
		temp.IPs = make(map[string]struct{})
	}

	return nil
}

type ipsetStore struct {
	ipsets map[string]*ipList
}

func newIpsetStore() *ipsetStore {
	return &ipsetStore{
		ipsets: make(map[string]*ipList),
	}
}

// clone returns a deep copy of the ipsetStore with its own ipsets map and
// independent ipList entries.
func (s *ipsetStore) clone() *ipsetStore {
	if s == nil {
		return nil
	}
	cloned := &ipsetStore{ipsets: make(map[string]*ipList, len(s.ipsets))}
	for name, list := range s.ipsets {
		cloned.ipsets[name] = list.clone()
	}
	return cloned
}

func (s *ipsetStore) ipset(ipsetName string) (*ipList, bool) {
	r, ok := s.ipsets[ipsetName]
	return r, ok
}

func (s *ipsetStore) addIpList(ipsetName string, list *ipList) {
	s.ipsets[ipsetName] = list
}

func (s *ipsetStore) deleteIpset(ipsetName string) {
	delete(s.ipsets, ipsetName)
}

func (s *ipsetStore) ipsetNames() []string {
	names := make([]string, 0, len(s.ipsets))
	for name := range s.ipsets {
		names = append(names, name)
	}
	return names
}

// MarshalJSON implements json.Marshaler
func (s *ipsetStore) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		IPSets map[string]*ipList `json:"ipsets"`
	}{
		IPSets: s.ipsets,
	})
}

// UnmarshalJSON implements json.Unmarshaler
func (s *ipsetStore) UnmarshalJSON(data []byte) error {
	temp := struct {
		IPSets map[string]*ipList `json:"ipsets"`
	}{}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	s.ipsets = temp.IPSets

	if temp.IPSets == nil {
		temp.IPSets = make(map[string]*ipList)
	}

	return nil
}
