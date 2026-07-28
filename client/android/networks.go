//go:build android

package android

type Network struct {
	Name       string
	Network    string
	Peer       string
	Status     string
	IsSelected bool
	Domains    NetworkDomains
}

func (n Network) GetNetworkDomains() *NetworkDomains {
	return &n.Domains
}

type NetworkArray struct {
	items []Network
}

func (array *NetworkArray) Add(s Network) *NetworkArray {
	array.items = append(array.items, s)
	return array
}

func (array *NetworkArray) Get(i int) *Network {
	return &array.items[i]
}

func (array *NetworkArray) Size() int {
	return len(array.items)
}
