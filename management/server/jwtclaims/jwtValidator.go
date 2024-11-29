package jwtclaims

import (
	"context"
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
}

// Jwks is a collection of JSONWebKey obtained from Config.HttpServerConfig.AuthKeysLocation
type Jwks struct {
	Keys          []JSONWebKey `json:"keys"`
	expiresInTime time.Time
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

type JWTValidator interface {
	ValidateAndParse(ctx context.Context, token string) (*jwt.Token, error)
}

// jwtValidatorImpl struct to handle token validation and parsing
type jwtValidatorImpl struct {
	options Options
}

var keyNotFound = errors.New("unable to find appropriate key")

// NewJWTValidator constructor
func NewJWTValidator(ctx context.Context, issuer string, audienceList []string, keysLocation string, idpSignkeyRefreshEnabled bool) (JWTValidator, error) {
	keys, err := getPemKeys(ctx, keysLocation)
	if err != nil {
		return nil, err
	}

	var lock sync.Mutex
	options := Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			// Verify 'aud' claim
			var checkAud bool
			for _, audience := range audienceList {
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

					refreshedKeys, err := getPemKeys(ctx, keysLocation)
					if err != nil {
						log.WithContext(ctx).Debugf("cannot get JSONWebKey: %v, falling back to old keys", err)
						refreshedKeys = keys
					}

					log.WithContext(ctx).Debugf("keys refreshed, new UTC expiration time: %s", refreshedKeys.expiresInTime.UTC())

					keys = refreshedKeys
				}
			}

			publicKey, err := getPublicKey(ctx, token, keys)
			if err == nil {
				return publicKey, nil
			}

			msg := fmt.Sprintf("getPublicKey error: %s", err)
			if errors.Is(err, keyNotFound) && !idpSignkeyRefreshEnabled {
				msg = fmt.Sprintf("getPublicKey error: %s. You can enable key refresh by setting HttpServerConfig.IdpSignKeyRefreshEnabled to true in your management.json file and restart the service", err)
			}

			log.WithContext(ctx).Error(msg)

			return nil, err
		},
		EnableAuthOnOptions: false,
	}

	if options.UserProperty == "" {
		options.UserProperty = "user"
	}

	return &jwtValidatorImpl{
		options: options,
	}, nil
}

// ValidateAndParse validates the token and returns the parsed token
func (m *jwtValidatorImpl) ValidateAndParse(ctx context.Context, token string) (*jwt.Token, error) {
	// If the token is empty...
	if token == "" {
		// Check if it was required
		if m.options.CredentialsOptional {
			log.WithContext(ctx).Debugf("no credentials found (CredentialsOptional=true)")
			// No error, just no token (and that is ok given that CredentialsOptional is true)
			return nil, nil //nolint:nilnil
		}

		// If we get here, the required token is missing
		errorMsg := "required authorization token not found"
		log.WithContext(ctx).Debugf("  Error: No credentials found (CredentialsOptional=false)")
		return nil, errors.New(errorMsg)
	}

	// Now parse the token
	parsedToken, err := jwt.Parse(token, m.options.ValidationKeyGetter)

	// Check if there was an error in parsing...
	if err != nil {
		log.WithContext(ctx).Errorf("error parsing token: %v", err)
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	// Check if the parsed token is valid...
	if !parsedToken.Valid {
		errorMsg := "token is invalid"
		log.WithContext(ctx).Debug(errorMsg)
		return nil, errors.New(errorMsg)
	}

	return parsedToken, nil
}

// stillValid returns true if the JSONWebKey still valid and have enough time to be used
func (jwks *Jwks) stillValid() bool {
	return !jwks.expiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(jwks.expiresInTime)
}

func getPemKeys(ctx context.Context, keysLocation string) (*Jwks, error) {
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
	expiresIn := getMaxAgeFromCacheHeader(ctx, cacheControlHeader)
	jwks.expiresInTime = time.Now().Add(time.Duration(expiresIn) * time.Second)

	return jwks, err
}

func getPublicKey(ctx context.Context, token *jwt.Token, jwks *Jwks) (interface{}, error) {
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
			log.WithContext(ctx).Debugf("generating PublicKey from RSA JWK")
			return getPublicKeyFromRSA(jwks.Keys[k])
		}
		if jwks.Keys[k].Kty == "EC" {
			log.WithContext(ctx).Debugf("generating PublicKey from ECDSA JWK")
			return getPublicKeyFromECDSA(jwks.Keys[k])
		}

		log.WithContext(ctx).Debugf("Key Type: %s not yet supported, please raise ticket!", jwks.Keys[k].Kty)
	}

	return nil, keyNotFound
}

func getPublicKeyFromECDSA(jwk JSONWebKey) (publicKey *ecdsa.PublicKey, err error) {

	if jwk.X == "" || jwk.Y == "" || jwk.Crv == "" {
		return nil, fmt.Errorf("ecdsa key incomplete")
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

func getPublicKeyFromRSA(jwk JSONWebKey) (*rsa.PublicKey, error) {

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
func getMaxAgeFromCacheHeader(ctx context.Context, cacheControl string) int {
	// Split into individual directives
	directives := strings.Split(cacheControl, ",")

	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(directive, "max-age=") {
			// Extract the max-age value
			maxAgeStr := strings.TrimPrefix(directive, "max-age=")
			maxAge, err := strconv.Atoi(maxAgeStr)
			if err != nil {
				log.WithContext(ctx).Debugf("error parsing max-age: %v", err)
				return 0
			}

			return maxAge
		}
	}

	return 0
}

type JwtValidatorMock struct{}

func (j *JwtValidatorMock) ValidateAndParse(ctx context.Context, token string) (*jwt.Token, error) {
	claimMaps := jwt.MapClaims{}

	switch token {
	case "testUserId", "testAdminId", "testOwnerId", "testServiceUserId", "testServiceAdminId", "blockedUserId":
		claimMaps[UserIDClaim] = token
		claimMaps[AccountIDSuffix] = "testAccountId"
		claimMaps[DomainIDSuffix] = "test.com"
		claimMaps[DomainCategorySuffix] = "private"
	case "otherUserId":
		claimMaps[UserIDClaim] = "otherUserId"
		claimMaps[AccountIDSuffix] = "otherAccountId"
		claimMaps[DomainIDSuffix] = "other.com"
		claimMaps[DomainCategorySuffix] = "private"
	case "invalidToken":
		return nil, errors.New("invalid token")
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claimMaps)
	return jwtToken, nil
}

