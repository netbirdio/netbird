package pkcs11

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math"
	"math/big"
)

var curvesByOID = map[string]elliptic.Curve{
	"1.2.840.10045.3.1.7": elliptic.P256(),
	"1.3.132.0.34":        elliptic.P384(),
	"1.3.132.0.35":        elliptic.P521(),
}

// PublicKey reads a CKO_PUBLIC_KEY object as a Go public key. RSA and EC keys are
// supported, the two kinds a certificate posture proof can be signed with.
func (s *Session) PublicKey(obj Object) (crypto.PublicKey, error) {
	raw, err := s.Attribute(obj, AttrKeyType)
	if err != nil {
		return nil, err
	}
	keyType, err := ulongValue(raw)
	if err != nil {
		return nil, fmt.Errorf("CKA_KEY_TYPE: %w", err)
	}
	switch keyType {
	case KeyRSA:
		modulus, exponent, err := s.attributes(obj, AttrModulus, AttrPublicExponent)
		if err != nil {
			return nil, err
		}
		return rsaPublicKey(modulus, exponent)
	case KeyEC:
		params, point, err := s.attributes(obj, AttrECParams, AttrECPoint)
		if err != nil {
			return nil, err
		}
		return ecPublicKey(params, point)
	}
	return nil, fmt.Errorf("unsupported key type 0x%x", keyType)
}

func (s *Session) attributes(obj Object, first, second uint) ([]byte, []byte, error) {
	a, err := s.Attribute(obj, first)
	if err != nil {
		return nil, nil, err
	}
	b, err := s.Attribute(obj, second)
	if err != nil {
		return nil, nil, err
	}
	return a, b, nil
}

func rsaPublicKey(modulus, exponent []byte) (*rsa.PublicKey, error) {
	e := new(big.Int).SetBytes(exponent)
	if e.Sign() <= 0 || e.Cmp(big.NewInt(math.MaxInt32)) > 0 {
		return nil, errors.New("CKA_PUBLIC_EXPONENT is out of range")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(e.Int64())}, nil
}

// ecPublicKey decodes CKA_EC_PARAMS, the named curve OID, and CKA_EC_POINT, the
// uncompressed point wrapped in a DER OCTET STRING, which some modules hand out bare.
func ecPublicKey(params, point []byte) (*ecdsa.PublicKey, error) {
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(params, &oid); err != nil {
		return nil, fmt.Errorf("CKA_EC_PARAMS: %w", err)
	}
	curve, ok := curvesByOID[oid.String()]
	if !ok {
		return nil, fmt.Errorf("unsupported curve %s", oid)
	}
	size := (curve.Params().BitSize + 7) / 8
	raw := point
	if len(raw) != 1+2*size {
		if _, err := asn1.Unmarshal(point, &raw); err != nil {
			return nil, fmt.Errorf("CKA_EC_POINT: %w", err)
		}
	}
	if len(raw) != 1+2*size || raw[0] != 4 {
		return nil, errors.New("CKA_EC_POINT is not an uncompressed point")
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(raw[1 : 1+size]),
		Y:     new(big.Int).SetBytes(raw[1+size:]),
	}, nil
}
