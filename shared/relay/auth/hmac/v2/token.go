package v2

import "errors"

type Token struct {
	AuthAlgo  AuthAlgo
	Signature []byte
	Payload   []byte
}

func (t *Token) Marshal() []byte {
	size := 1 + len(t.Signature) + len(t.Payload)

	buf := make([]byte, size)

	buf[0] = byte(t.AuthAlgo)
	copy(buf[1:], t.Signature)
	copy(buf[1+len(t.Signature):], t.Payload)

	return buf
}

func UnmarshalToken(data []byte) (*Token, error) {
	if len(data) == 0 {
		return nil, errors.New("invalid token data")
	}

	algo := AuthAlgo(data[0])
	sigSize := algo.Size()
	if len(data) < 1+sigSize {
		return nil, errors.New("invalid token data: insufficient length")
	}

	return &Token{
		AuthAlgo:  algo,
		Signature: data[1 : 1+sigSize],
		Payload:   data[1+sigSize:],
	}, nil
}
