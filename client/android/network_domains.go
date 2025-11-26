//go:build android

package android

import "fmt"

type ResolvedIPs struct {
	resolvedIPs []string
}

func (r *ResolvedIPs) Add(ipAddress string) {
	r.resolvedIPs = append(r.resolvedIPs, ipAddress)
}

func (r *ResolvedIPs) Get(i int) (string, error) {
	if i < 0 || i >= len(r.resolvedIPs) {
		return "", fmt.Errorf("%d is out of range", i)
	}
	return r.resolvedIPs[i], nil
}

func (r *ResolvedIPs) Size() int {
	return len(r.resolvedIPs)
}

type NetworkDomain struct {
	Address     string
	resolvedIPs ResolvedIPs
}

func (d *NetworkDomain) addResolvedIP(resolvedIP string) {
	d.resolvedIPs.Add(resolvedIP)
}

func (d *NetworkDomain) GetResolvedIPs() *ResolvedIPs {
	return &d.resolvedIPs
}

type NetworkDomains struct {
	domains []*NetworkDomain
}

func (n *NetworkDomains) Add(domain *NetworkDomain) {
	n.domains = append(n.domains, domain)
}

func (n *NetworkDomains) Get(i int) (*NetworkDomain, error) {
	if i < 0 || i >= len(n.domains) {
		return nil, fmt.Errorf("%d is out of range", i)
	}
	return n.domains[i], nil
}

func (n *NetworkDomains) Size() int {
	return len(n.domains)
}
