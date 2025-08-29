// Deprecated: This package is deprecated and will be removed in a future release.
package auth

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

type Algorithm int

const (
	AlgoUnknown Algorithm = iota
	AlgoHMACSHA256
	AlgoHMACSHA512
)

func (a Algorithm) String() string {
	switch a {
	case AlgoHMACSHA256:
		return "HMAC-SHA256"
	case AlgoHMACSHA512:
		return "HMAC-SHA512"
	default:
		return "Unknown"
	}
}

type Msg struct {
	AuthAlgorithm  Algorithm
	AdditionalData []byte
}

func UnmarshalMsg(data []byte) (*Msg, error) {
	var msg *Msg

	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&msg); err != nil {
		return nil, fmt.Errorf("decode Msg: %w", err)
	}
	return msg, nil
}
