package android

type PeerInfo struct {
	IP         string
	FQDN       string
	ConnStatus string
	Direct     bool
}

type PeerInfoCollection interface {
	Add(s string) PeerInfoCollection
	Get(i int) string
	Size() int
}

type PeerInfoArray struct {
	items []PeerInfo
}

func (array PeerInfoArray) Add(s PeerInfo) PeerInfoArray {
	array.items = append(array.items, s)
	return array
}

func (array PeerInfoArray) Get(i int) *PeerInfo {
	return &array.items[i]
}

func (array PeerInfoArray) Size() int {
	return len(array.items)
}
