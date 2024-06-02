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
	Selected bool
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
