package android

import "fmt"

// DNSList is a wrapper of []string
type DNSList struct {
	items []string
}

// Add new DNS address to the collection
func (array *DNSList) Add(s string) {
	array.items = append(array.items, s)
}

// Get return an element of the collection
func (array *DNSList) Get(i int) (string, error) {
	if i >= len(array.items) || i < 0 {
		return "", fmt.Errorf("out of range")
	}
	return array.items[i], nil
}

// Size return with the size of the collection
func (array *DNSList) Size() int {
	return len(array.items)
}
