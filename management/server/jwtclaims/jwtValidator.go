package jwtclaims

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

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

// The supported elliptic curves types
const (
	// p256 represents a cryptographic elliptical curve type.
	p256 = "P-256"

	// p384 represents a cryptographic elliptical curve type.
	p384 = "P-384"

	// p521 represents a cryptographic elliptical curve type.
	p521 = "P-521"
)

// Jwks is a collection of JSONWebKey obtained from Config.HttpServerConfig.AuthKeysLocation
type Jwks struct {
	Keys          []JSONWebKey `json:"keys"`
	expiresInTime time.Time
}

// JSONWebKey is a representation of a Jason Web Key
type JSONWebKey struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
 	Crv string   `json:"crv"`
	X   string   `json:"x"`
	Y   string   `json:"y"`
	X5c []string `json:"x5c"`
}

// JWTValidator struct to handle token validation and parsing
type JWTValidator struct {
	options Options
}

// NewJWTValidator constructor
func NewJWTValidator(issuer string, audienceList []string, keysLocation string, idpSignkeyRefreshEnabled bool) (*JWTValidator, error) {
	keys, err := getPemKeys(keysLocation)
	if err != nil {
		return nil, err
	}
				log.Debugf("ISSUER: %s", issuer)

	var lock sync.Mutex
	options := Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			// Verify 'aud' claim

			var checkAud bool
			for _, audience := range audienceList {
				log.Debugf("AUDUENCE: %s", audience)
				checkAud = token.Claims.(jwt.MapClaims).VerifyAudience(audience, false)
				if checkAud {
					break
				}
			}
			if !checkAud {
				return token, errors.New("invalid audience")
			}
			// Verify 'issuer' claim
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(issuer, false)
			if !checkIss {
				return token, errors.New("invalid issuer")
			}

			// If keys are rotated, verify the keys prior to token validation
			if idpSignkeyRefreshEnabled {
				// If the keys are invalid, retrieve new ones
				if !keys.stillValid() {
					lock.Lock()
					defer lock.Unlock()

					refreshedKeys, err := getPemKeys(keysLocation)
					if err != nil {
						log.Debugf("cannot get JSONWebKey: %v, falling back to old keys", err)
						refreshedKeys = keys
					}

					log.Debugf("keys refreshed, new UTC expiration time: %s", refreshedKeys.expiresInTime.UTC())

					keys = refreshedKeys
				}
			}

			publicKey, err := getPublicKey(token, keys)
			if err != nil {
				log.Errorf("getPublicKey error: %s", err)
				return nil, err
			}

			return publicKey, nil
		},
		SigningMethod:       nil, //jwt.SigningMethodRS256,
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
			return nil, nil //nolint:nilnil
		}

		// If we get here, the required token is missing
		errorMsg := "required authorization token not found"
		log.Debugf("  Error: No credentials found (CredentialsOptional=false)")
		return nil, fmt.Errorf("%s", errorMsg)
	}

	// Now parse the token
	parsedToken, err := jwt.Parse(token, m.options.ValidationKeyGetter)

	// Check if there was an error in parsing...
	if err != nil {
		log.Errorf("error parsing token: %v", err)
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
		log.Debugf("Error: %s", errorMsg)
		return nil, errors.New(errorMsg)
	}

	return parsedToken, nil
}

// stillValid returns true if the JSONWebKey still valid and have enough time to be used
func (jwks *Jwks) stillValid() bool {
	return !jwks.expiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(jwks.expiresInTime)
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

	cacheControlHeader := resp.Header.Get("Cache-Control")
	expiresIn := getMaxAgeFromCacheHeader(cacheControlHeader)
	jwks.expiresInTime = time.Now().Add(time.Duration(expiresIn) * time.Second)

	return jwks, err
}

func getPublicKey(token *jwt.Token, jwks *Jwks) (interface{}, error) {
	// todo as we load the jkws when the server is starting, we should build a JKS map with the pem cert at the boot time

	for k := range jwks.Keys {
		if token.Header["kid"] != jwks.Keys[k].Kid {
			continue
		}

		if len(jwks.Keys[k].X5c) != 0 {
			cert := "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
			return jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		}

		if jwks.Keys[k].Kty == "RSA" {
			log.Debugf("generating PublicKey from RSA JWK")
			return getPublicKeyFromJWK_RSA(jwks.Keys[k])
		}
		if jwks.Keys[k].Kty == "EC" {
			log.Debugf("generating PublicKey from ECDSA JWK")
			return getPublicKeyFromJWK_ECDSA(jwks.Keys[k])
		}

		log.Debugf("Key Type: %s not yet supported, please raise ticket !", jwks.Keys[k].Kty)
	}

	return nil, errors.New("unable to find appropriate key")
}

func getPublicKeyFromJWK_ECDSA(jwk JSONWebKey) (publicKey *ecdsa.PublicKey, err error) {

	if jwk.X == "" || jwk.Y == "" || jwk.Crv == "" {
		return nil, fmt.Errorf("ecdsa key incompleet")
	}

	var xCoordinate []byte
	if xCoordinate, err = base64.RawURLEncoding.DecodeString(jwk.X); err != nil {
		return nil, err
	}

	var yCoordinate []byte
	if yCoordinate, err = base64.RawURLEncoding.DecodeString(jwk.Y); err != nil {
		return nil, err
	}

	publicKey = &ecdsa.PublicKey{}

	var curve elliptic.Curve
	switch jwk.Crv {
	case p256:
		curve = elliptic.P256()
	case p384:
		curve = elliptic.P384()
	case p521:
		curve = elliptic.P521()
	}

	publicKey.Curve = curve
	publicKey.X = big.NewInt(0).SetBytes(xCoordinate)
	publicKey.Y = big.NewInt(0).SetBytes(yCoordinate)

	return publicKey, nil
}

func getPublicKeyFromJWK_RSA(jwk JSONWebKey) (*rsa.PublicKey, error) {

        decodedE, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	decodedN, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}

	var n, e big.Int
	e.SetBytes(decodedE)
	n.SetBytes(decodedN)

	return &rsa.PublicKey{
		E: int(e.Int64()),
		N: &n,
	}, nil
}

// getMaxAgeFromCacheHeader extracts max-age directive from the Cache-Control header
func getMaxAgeFromCacheHeader(cacheControl string) int {
	// Split into individual directives
	directives := strings.Split(cacheControl, ",")

	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(directive, "max-age=") {
			// Extract the max-age value
			maxAgeStr := strings.TrimPrefix(directive, "max-age=")
			maxAge, err := strconv.Atoi(maxAgeStr)
			if err != nil {
				log.Debugf("error parsing max-age: %v", err)
				return 0
			}

			return maxAge
		}
	}

	return 0
}
