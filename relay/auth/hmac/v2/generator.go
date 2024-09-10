package v2

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"time"
)

type Generator struct {
	algo       func() hash.Hash
	secret     []byte
	timeToLive time.Duration
}

func NewGenerator(algo AuthAlgo, secret []byte, timeToLive time.Duration) (*Generator, error) {
	algoFunc := algo.New()
	if algoFunc == nil {
		return nil, fmt.Errorf("unsupported auth algorithm: %s", algo)
	}
	return &Generator{
		algo:       algoFunc,
		secret:     secret,
		timeToLive: timeToLive,
	}, nil
}

func (g *Generator) GenerateToken() (*Token, error) {
	expirationTime := time.Now().Add(g.timeToLive).Unix()

	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(expirationTime))

	h := hmac.New(g.algo, g.secret)
	h.Write(payload)
	signature := h.Sum(nil)

	return &Token{
		Signature: signature,
		Payload:   payload,
	}, nil
}
