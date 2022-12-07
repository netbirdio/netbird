package middleware

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
	"math/big"
	"net/http"
)

// Jwks is a collection of JSONWebKey obtained from Config.HttpServerConfig.AuthKeysLocation
type Jwks struct {
	Keys []JSONWebKey `json:"keys"`
}

// JSONWebKey is a representation of a Jason Web Key
type JSONWebKey struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// NewJwtMiddleware creates new middleware to verify the JWT token sent via Authorization header
func NewJwtMiddleware(issuer string, audience string, keysLocation string) (*JWTMiddleware, error) {

	keys, err := getPemKeys(keysLocation)
	if err != nil {
		return nil, err
	}

	return New(Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			// Verify 'aud' claim
			checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(audience, false)
			if !checkAud {
				return token, errors.New("invalid audience")
			}
			// Verify 'issuer' claim
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(issuer, false)
			if !checkIss {
				return token, errors.New("invalid issuer")
			}

			cert, err := getPemCert(token, keys)
			if err != nil {
				return nil, err
			}

			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		},
		SigningMethod:       jwt.SigningMethodRS256,
		EnableAuthOnOptions: false,
	}), nil
}

func getPemKeys(keysLocation string) (*Jwks, error) {
	resp, err := http.Get(keysLocation)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jwks = &Jwks{}
	err = json.NewDecoder(resp.Body).Decode(jwks)
	if err != nil {
		return jwks, err
	}

	return jwks, err
}

func getPemCert(token *jwt.Token, jwks *Jwks) (string, error) {
	// todo as we load the jkws when the server is starting, we should build a JKS map with the pem cert at the boot time
	cert := ""

	for k := range jwks.Keys {
		if token.Header["kid"] != jwks.Keys[k].Kid {
			continue
		}

		if len(jwks.Keys[k].X5c) != 0 {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
			return cert, nil
		} else {
			log.Debugf("generating validation pem from JWK")
			return generatePemFromJWK(jwks.Keys[k])
		}
	}

	return "", errors.New("unable to find appropriate key")
}

func generatePemFromJWK(jwk JSONWebKey) (string, error) {
	decodedModulus, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return "", fmt.Errorf("unable to decode JWK modulus, error: %s", err)
	}

	intModules := big.NewInt(0)
	intModules.SetBytes(decodedModulus)

	exponent, err := convertExponentStringToInt(jwk.E)
	if err != nil {
		return "", fmt.Errorf("unable to decode JWK exponent, error: %s", err)
	}

	publicKey := &rsa.PublicKey{
		N: intModules,
		E: exponent,
	}

	derKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("unable to convert public key to DER, error: %s", err)
	}

	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derKey,
	}

	var out bytes.Buffer
	err = pem.Encode(&out, block)
	if err != nil {
		return "", fmt.Errorf("unable to encode Pem block , error: %s", err)
	}

	return out.String(), nil
}

func convertExponentStringToInt(stringExponent string) (int, error) {
	decodedString, err := base64.StdEncoding.DecodeString(stringExponent)
	if err != nil {
		return 0, err
	}
	exponentBytes := decodedString
	if len(decodedString) < 8 {
		exponentBytes = make([]byte, 8-len(decodedString), 8)
		exponentBytes = append(exponentBytes, decodedString...)
	}

	bytesReader := bytes.NewReader(exponentBytes)
	var exponent uint64
	err = binary.Read(bytesReader, binary.BigEndian, &exponent)
	if err != nil {
		return 0, err
	}

	return int(exponent), nil
}
