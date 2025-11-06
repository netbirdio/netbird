package sign

import (
	"encoding/json"
	"fmt"
	"time"
)

// RevocationList contains revoked Key IDs and their revocation timestamps
type RevocationList struct {
	Revoked map[KeyID]time.Time `json:"revoked"` // KeyID -> revocation time
}

func ParseRevocationList(data []byte) (*RevocationList, error) {
	var rl RevocationList
	if err := json.Unmarshal(data, &rl); err != nil {
		return nil, fmt.Errorf("failed to unmarshal revocation list: %w", err)
	}

	// Initialize the map if it's nil (in case of empty JSON object)
	if rl.Revoked == nil {
		rl.Revoked = make(map[KeyID]time.Time)
	}

	return &rl, nil
}
