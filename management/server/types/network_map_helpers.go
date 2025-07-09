package types

import (
	"encoding/json"
)

// SerializeNetworkMap serializes a NetworkMap to JSON
func SerializeNetworkMap(nm *NetworkMap) ([]byte, error) {
	return json.Marshal(nm)
}

// DeserializeNetworkMap deserializes JSON data into a NetworkMap
func DeserializeNetworkMap(data []byte) (*NetworkMap, error) {
	var nm NetworkMap
	err := json.Unmarshal(data, &nm)
	return &nm, err
}
