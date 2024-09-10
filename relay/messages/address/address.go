// Deprecated: This package is deprecated and will be removed in a future release.
package address

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

type Address struct {
	URL string
}

func (addr *Address) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(addr); err != nil {
		return nil, fmt.Errorf("encode Address: %w", err)
	}
	return buf.Bytes(), nil
}
