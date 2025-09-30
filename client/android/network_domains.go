package android

import "fmt"

type NetworkDomains struct {
	domains []string
}

func (n *NetworkDomains) Add(domain string) {
	n.domains = append(n.domains, domain)
}

func (n *NetworkDomains) Get(i int) (string, error) {
	if i < 0 || i >= len(n.domains) {
		return "", fmt.Errorf("%d is out of range", i)
	}
	return n.domains[i], nil
}

func (n *NetworkDomains) Size() int {
	return len(n.domains)
}
