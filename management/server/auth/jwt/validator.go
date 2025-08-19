package jwt

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
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	log "github.com/sirupsen/logrus"
)

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

type Validator struct {
	lock                     sync.Mutex
	issuer                   string
	audienceList             []string
	keysLocation             string
	idpSignkeyRefreshEnabled bool
	keys                     *Jwks
}

var (
	errKeyNotFound     = errors.New("unable to find appropriate key")
	errInvalidAudience = errors.New("invalid audience")
	errInvalidIssuer   = errors.New("invalid issuer")
	errTokenEmpty      = errors.New("required authorization token not found")
	errTokenInvalid    = errors.New("token is invalid")
	errTokenParsing    = errors.New("token could not be parsed")
)

func NewValidator(issuer string, audienceList []string, keysLocation string, idpSignkeyRefreshEnabled bool) *Validator {
	keys, err := getPemKeys(keysLocation)
	if err != nil {
		log.WithField("keysLocation", keysLocation).Errorf("could not get keys from location: %s", err)
	}

	return &Validator{
		keys:                     keys,
		issuer:                   issuer,
		audienceList:             audienceList,
		keysLocation:             keysLocation,
		idpSignkeyRefreshEnabled: idpSignkeyRefreshEnabled,
	}
}

func (v *Validator) getKeyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, errors.New("invalid claims type")
		}

		// Verify 'aud' claim
		audiences, err := claims.GetAudience()
		if err != nil {
			return nil, fmt.Errorf("get claim audience: %w", err)
		}

		checkAud := false
		for _, audience := range v.audienceList {
			if slices.Contains(audiences, audience) {
				checkAud = true
				break
			}
		}

		if !checkAud {
			return nil, errInvalidAudience
		}

		// Verify 'issuer' claim
		issuer, err := claims.GetIssuer()
		if err != nil {
			return nil, fmt.Errorf("failed to get claim issuer: %w", err)
		}
		if issuer != v.issuer {
			return nil, errInvalidIssuer
		}

		// If keys are rotated, verify the keys prior to token validation
		if v.idpSignkeyRefreshEnabled {
			// If the keys are invalid, retrieve new ones
			// @todo propose a separate go routine to regularly check these to prevent blocking when actually
			// validating the token
			if !v.keys.stillValid() {
				v.lock.Lock()
				defer v.lock.Unlock()

				refreshedKeys, err := getPemKeys(v.keysLocation)
				if err != nil {
					log.WithContext(ctx).Debugf("cannot get JSONWebKey: %v, falling back to old keys", err)
					refreshedKeys = v.keys
				}

				log.WithContext(ctx).Debugf("keys refreshed, new UTC expiration time: %s", refreshedKeys.expiresInTime.UTC())

				v.keys = refreshedKeys
			}
		}

		publicKey, err := getPublicKey(token, v.keys)
		if err == nil {
			return publicKey, nil
		}

		msg := fmt.Sprintf("getPublicKey error: %s", err)
		if errors.Is(err, errKeyNotFound) && !v.idpSignkeyRefreshEnabled {
			msg = fmt.Sprintf("getPublicKey error: %s. You can enable key refresh by setting HttpServerConfig.IdpSignKeyRefreshEnabled to true in your management.json file and restart the service", err)
		}

		log.WithContext(ctx).Error(msg)

		return nil, err
	}
}

// ValidateAndParse validates the token and returns the parsed token
func (v *Validator) ValidateAndParse(ctx context.Context, token string) (*jwt.Token, error) {
	// If the token is empty...
	if token == "" {
		// If we get here, the required token is missing
		log.WithContext(ctx).Debugf("  Error: No credentials found (CredentialsOptional=false)")
		return nil, errTokenEmpty
	}

	// Now parse the token
	parsedToken, err := jwt.Parse(token, v.getKeyFunc(ctx))

	// Check if there was an error in parsing...
	if err != nil {
		err = fmt.Errorf("%w: %s", errTokenParsing, err)
		log.WithContext(ctx).Error(err.Error())
		return nil, err
	}

	// Check if the parsed token is valid...
	if !parsedToken.Valid {
		log.WithContext(ctx).Debug(errTokenInvalid.Error())
		return nil, errTokenInvalid
	}

	return parsedToken, nil
}

// stillValid returns true if the JSONWebKey still valid and have enough time to be used
func (jwks *Jwks) stillValid() bool {
	return !jwks.expiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(jwks.expiresInTime)
}

func getPemKeys(keysLocation string) (*Jwks, error) {
	jwks := &Jwks{}

	url, err := url.ParseRequestURI(keysLocation)
	if err != nil {
		return jwks, err
	}

	resp, err := http.Get(url.String())
	if err != nil {
		return jwks, err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(jwks)
	if err != nil {
		return jwks, err
	}

	cacheControlHeader := resp.Header.Get("Cache-Control")
	expiresIn := getMaxAgeFromCacheHeader(cacheControlHeader)
	jwks.expiresInTime = time.Now().Add(time.Duration(expiresIn) * time.Second)

	return jwks, nil
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
			return getPublicKeyFromRSA(jwks.Keys[k])
		}
		if jwks.Keys[k].Kty == "EC" {
			return getPublicKeyFromECDSA(jwks.Keys[k])
		}
	}

	return nil, errKeyNotFound
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
				return 0
			}

			return maxAge
		}
	}

	return 0
}
