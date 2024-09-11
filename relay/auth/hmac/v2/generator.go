package v2

import (
	"crypto/hmac"
	"fmt"
	"hash"
	"strconv"
	"time"
)

type Generator struct {
	algo       func() hash.Hash
	algoType   AuthAlgo
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
		algoType:   algo,
		secret:     secret,
		timeToLive: timeToLive,
	}, nil
}

func (g *Generator) GenerateToken() (*Token, error) {
	expirationTime := time.Now().Add(g.timeToLive).Unix()

	payload := []byte(strconv.FormatInt(expirationTime, 10))

	h := hmac.New(g.algo, g.secret)
	h.Write(payload)
	signature := h.Sum(nil)

	return &Token{
		AuthAlgo:  g.algoType,
		Signature: signature,
		Payload:   payload,
	}, nil
}
