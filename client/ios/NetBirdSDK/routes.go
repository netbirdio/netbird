//go:build ios

package NetBirdSDK

// RoutesSelectionInfoCollection made for Java layer to get non default types as collection
type RoutesSelectionInfoCollection interface {
	Add(s string) RoutesSelectionInfoCollection
	Get(i int) string
	Size() int
}

type RoutesSelectionDetails struct {
	All    bool
	Append bool
	items  []RoutesSelectionInfo
}

type RoutesSelectionInfo struct {
	ID       string
	Network  string
	Domains  *DomainDetails
	Selected bool
}

type DomainCollection interface {
	Add(s DomainInfo) DomainCollection
	Get(i int) *DomainInfo
	Size() int
}

type DomainDetails struct {
	items []DomainInfo
}

type DomainInfo struct {
	Domain      string
	ResolvedIPs string
}

// Add new PeerInfo to the collection
func (array RoutesSelectionDetails) Add(s RoutesSelectionInfo) RoutesSelectionDetails {
	array.items = append(array.items, s)
	return array
}

// Get return an element of the collection
func (array RoutesSelectionDetails) Get(i int) *RoutesSelectionInfo {
	return &array.items[i]
}

// Size return with the size of the collection
func (array RoutesSelectionDetails) Size() int {
	return len(array.items)
}

func (array DomainDetails) Add(s DomainInfo) DomainCollection {
	array.items = append(array.items, s)
	return array
}

func (array DomainDetails) Get(i int) *DomainInfo {
	return &array.items[i]
}

func (array DomainDetails) Size() int {
	return len(array.items)
}
