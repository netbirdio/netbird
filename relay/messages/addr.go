package messages

import (
	"encoding/json"
	"fmt"
	"strings"
)

type FeatureVersionCode uint16

const (
	VersionUnknown      FeatureVersionCode = 0
	VersionSubscription FeatureVersionCode = 1
)

type RelayAddr struct {
	Addr               string             `json:"ExposedAddr,omitempty"`
	FeatureVersionCode FeatureVersionCode `json:"Version,omitempty"`
}

func (a RelayAddr) Network() string {
	return "relay"
}

func (a RelayAddr) String() string {
	return a.Addr
}

// UnmarshalRelayAddr json encoded RelayAddr data.
func UnmarshalRelayAddr(data []byte) (*RelayAddr, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("unmarshalRelayAddr: empty data")
	}

	var addr RelayAddr
	if err := json.Unmarshal(data, &addr); err != nil {
		addrString, err := fallbackToOldFormat(data)
		if err != nil {
			return nil, fmt.Errorf("failed to fallback to old auth message: %v", err)
		}
		return &RelayAddr{Addr: addrString}, nil
	}

	if addr.Addr == "" {
		return nil, fmt.Errorf("unmarshalRelayAddr: empty address in RelayAddr")
	}
	return &addr, nil
}

func fallbackToOldFormat(data []byte) (string, error) {
	addr := string(data)
	if !strings.HasPrefix(addr, "rel://") && !strings.HasPrefix(addr, "rels://") {
		return "", fmt.Errorf("invalid address: must start with rel:// or rels://: %s", addr)
	}
	return addr, nil
}
