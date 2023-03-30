package jwtclaims

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
	"math/big"
	"net/http"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
)

// Options is a struct for specifying configuration options for the middleware.
type Options struct {
	// The function that will return the Key to validate the JWT.
	// It can be either a shared secret or a public key.
	// Default value: nil
	ValidationKeyGetter jwt.Keyfunc
	// The name of the property in the request where the user information
	// from the JWT will be stored.
	// Default value: "user"
	UserProperty string
	// The function that will be called when there's an error validating the token
	// Default value:
	CredentialsOptional bool
	// A function that extracts the token from the request
	// Default: FromAuthHeader (i.e., from Authorization header as bearer token)
	Debug bool
	// When set, all requests with the OPTIONS method will use authentication
	// Default: false
	EnableAuthOnOptions bool
	// When set, the middelware verifies that tokens are signed with the specific signing algorithm
	// If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
	// Important to avoid security issues described here: https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
	// Default: nil
	SigningMethod jwt.SigningMethod
}

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

// JWTValidator struct to handle token validation and parsing
type JWTValidator struct {
	options Options
}

// NewJWTValidator constructor
func NewJWTValidator(issuer string, audience string, keysLocation string) (*JWTValidator, error) {
	keys, err := getPemKeys(keysLocation)
	if err != nil {
		return nil, err
	}

	options := Options{
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
	}

	if options.UserProperty == "" {
		options.UserProperty = "user"
	}

	return &JWTValidator{
		options: options,
	}, nil
}

// ValidateAndParse validates the token and returns the parsed token
func (m *JWTValidator) ValidateAndParse(token string) (*jwt.Token, error) {
	// If the token is empty...
	if token == "" {
		// Check if it was required
		if m.options.CredentialsOptional {
			log.Debugf("no credentials found (CredentialsOptional=true)")
			// No error, just no token (and that is ok given that CredentialsOptional is true)
			return nil, nil
		}

		// If we get here, the required token is missing
		errorMsg := "required authorization token not found"
		log.Debugf("  Error: No credentials found (CredentialsOptional=false)")
		return nil, fmt.Errorf(errorMsg)
	}

	// Now parse the token
	parsedToken, err := jwt.Parse(token, m.options.ValidationKeyGetter)

	// Check if there was an error in parsing...
	if err != nil {
		log.Debugf("error parsing token: %v", err)
		return nil, fmt.Errorf("Error parsing token: %w", err)
	}

	if m.options.SigningMethod != nil && m.options.SigningMethod.Alg() != parsedToken.Header["alg"] {
		errorMsg := fmt.Sprintf("Expected %s signing method but token specified %s",
			m.options.SigningMethod.Alg(),
			parsedToken.Header["alg"])
		log.Debugf("error validating token algorithm: %s", errorMsg)
		return nil, fmt.Errorf("error validating token algorithm: %s", errorMsg)
	}

	// Check if the parsed token is valid...
	if !parsedToken.Valid {
		errorMsg := "token is invalid"
		log.Debugf(errorMsg)
		return nil, errors.New(errorMsg)
	}

	return parsedToken, nil
}

func getPemKeys(keysLocation string) (*Jwks, error) {
	resp, err := http.Get(keysLocation)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	jwks := &Jwks{}
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
		}
		log.Debugf("generating validation pem from JWK")
		return generatePemFromJWK(jwks.Keys[k])
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
