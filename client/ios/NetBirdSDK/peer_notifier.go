//go:build ios

package NetBirdSDK

// PeerInfo describe information about the peers. It designed for the UI usage
type PeerInfo struct {
	IP                         string
	IPv6                       string
	FQDN                       string
	LocalIceCandidateEndpoint  string
	RemoteIceCandidateEndpoint string
	LocalIceCandidateType      string
	RemoteIceCandidateType     string
	PubKey                     string
	Latency                    string
	BytesRx                    int64
	BytesTx                    int64
	ConnStatus                 string
	ConnStatusUpdate           string
	Direct                     bool
	LastWireguardHandshake     string
	Relayed                    bool
	RosenpassEnabled           bool
	Routes                     RoutesDetails
}

// GetIPv6 returns the IPv6 address of the peer
func (p PeerInfo) GetIPv6() string {
	return p.IPv6
}

// GetRoutes return with RouteDetails
func (p PeerInfo) GetRouteDetails() *RoutesDetails {
	return &p.Routes
}

// PeerInfoCollection made for Java layer to get non default types as collection
type PeerInfoCollection interface {
	Add(s string) PeerInfoCollection
	Get(i int) string
	Size() int
	GetFQDN() string
	GetIP() string
}

// RoutesInfoCollection made for Java layer to get non default types as collection
type RoutesInfoCollection interface {
	Add(s string) RoutesInfoCollection
	Get(i int) string
	Size() int
}

type RoutesDetails struct {
	items []RoutesInfo
}

type RoutesInfo struct {
	Route string
}

// StatusDetails is the implementation of the PeerInfoCollection
type StatusDetails struct {
	items []PeerInfo
	fqdn  string
	ip    string
	ipv6  string
}

// Add new PeerInfo to the collection
func (array RoutesDetails) Add(s RoutesInfo) RoutesDetails {
	array.items = append(array.items, s)
	return array
}

// Get return an element of the collection
func (array RoutesDetails) Get(i int) *RoutesInfo {
	return &array.items[i]
}

// Size return with the size of the collection
func (array RoutesDetails) Size() int {
	return len(array.items)
}

// Add new PeerInfo to the collection
func (array StatusDetails) Add(s PeerInfo) StatusDetails {
	array.items = append(array.items, s)
	return array
}

// Get return an element of the collection
func (array StatusDetails) Get(i int) *PeerInfo {
	return &array.items[i]
}

// Size return with the size of the collection
func (array StatusDetails) Size() int {
	return len(array.items)
}

// GetFQDN return with the FQDN of the local peer
func (array StatusDetails) GetFQDN() string {
	return array.fqdn
}

// GetIP return with the IP of the local peer
func (array StatusDetails) GetIP() string {
	return array.ip
}

// GetIPv6 return with the IPv6 of the local peer
func (array StatusDetails) GetIPv6() string {
	return array.ipv6
}
