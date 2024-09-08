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

func Unmarshal(data []byte) (*Address, error) {
	var addr Address
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&addr); err != nil {
		return nil, fmt.Errorf("decode Address: %w", err)
	}
	return &addr, nil
}
