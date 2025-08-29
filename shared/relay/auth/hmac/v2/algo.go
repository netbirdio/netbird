package v2

import (
	"crypto/sha256"
	"hash"
)

const (
	AuthAlgoUnknown AuthAlgo = iota
	AuthAlgoHMACSHA256
)

type AuthAlgo uint8

func (a AuthAlgo) String() string {
	switch a {
	case AuthAlgoHMACSHA256:
		return "HMAC-SHA256"
	default:
		return "Unknown"
	}
}

func (a AuthAlgo) New() func() hash.Hash {
	switch a {
	case AuthAlgoHMACSHA256:
		return sha256.New
	default:
		return nil
	}
}

func (a AuthAlgo) Size() int {
	switch a {
	case AuthAlgoHMACSHA256:
		return sha256.Size
	default:
		return 0
	}
}
