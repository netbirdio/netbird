package route

import "strings"

const haSeparator = "|"

type HAUniqueID string

func (id HAUniqueID) String() string {
	return string(id)
}

// NetID returns the Network ID from the HAUniqueID
func (id HAUniqueID) NetID() NetID {
	if i := strings.LastIndex(string(id), haSeparator); i != -1 {
		return NetID(id[:i])
	}
	return NetID(id)
}
