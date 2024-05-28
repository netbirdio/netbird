package route

import "strings"

type HAUniqueID string

// GetHAUniqueID returns a highly available route ID by combining Network ID and Network range address
func GetHAUniqueID(input *Route) HAUniqueID {
	return HAUniqueID(string(input.NetID) + "-" + input.Network.String())
}

func (id HAUniqueID) String() string {
	return string(id)
}

// NetID returns the Network ID from the HAUniqueID
func (id HAUniqueID) NetID() NetID {
	if i := strings.LastIndex(string(id), "-"); i != -1 {
		return NetID(id[:i])
	}
	return NetID(id)
}
