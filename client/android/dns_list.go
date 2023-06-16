package android

// DNSList is a wrapper of []string
type DNSList struct {
	items []string
}

// Add new DNS address to the collection
func (array *DNSList) Add(s string) {
	array.items = append(array.items, s)
}

// Get return an element of the collection
func (array *DNSList) Get(i int) string {
	return array.items[i]
}

// Size return with the size of the collection
func (array *DNSList) Size() int {
	return len(array.items)
}
