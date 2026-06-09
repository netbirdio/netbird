package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
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
	ExpiresInTime time.Time    `json:"-"`
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

// KeyFetcher is a function that retrieves JWKS keys directly (e.g., from Dex storage)
// bypassing HTTP. When set on a Validator, it is used instead of the HTTP-based getPemKeys.
type KeyFetcher func(ctx context.Context) (*Jwks, error)

type Validator struct {
	lock                     sync.Mutex
	issuer                   string
	audienceList             []string
	keysLocation             string
	idpSignkeyRefreshEnabled bool
	keyFetcher               KeyFetcher
	keys                     *Jwks
	lastForcedRefresh        time.Time
}

var (
	errKeyNotFound  = errors.New("unable to find appropriate key")
	errTokenEmpty   = errors.New("required authorization token not found")
	errTokenInvalid = errors.New("token is invalid")
	errTokenParsing = errors.New("token could not be parsed")
	errUnsupportedKeyType = errors.New("unsupported key type")
)

func NewValidator(issuer string, audienceList []string, keysLocation string, idpSignkeyRefreshEnabled bool) *Validator {
	keys, err := getPemKeys(keysLocation)
	if err != nil && !strings.Contains(keysLocation, "localhost") {
		log.WithField("keysLocation", keysLocation).Warnf("could not get keys from location: %s, it will try again on the next http request", err)
	}

	return &Validator{
		keys:                     keys,
		issuer:                   issuer,
		audienceList:             audienceList,
		keysLocation:             keysLocation,
		idpSignkeyRefreshEnabled: idpSignkeyRefreshEnabled,
	}
}

// NewValidatorWithKeyFetcher creates a Validator that fetches keys directly using the
// provided KeyFetcher (e.g., from Dex storage) instead of via HTTP.
func NewValidatorWithKeyFetcher(issuer string, audienceList []string, keyFetcher KeyFetcher) *Validator {
	ctx := context.Background()
	keys, err := keyFetcher(ctx)
	if err != nil {
		log.Warnf("could not get keys from key fetcher: %s, it will try again on the next http request", err)
	}
	if keys == nil {
		keys = &Jwks{}
	}

	return &Validator{
		keys:                     keys,
		issuer:                   issuer,
		audienceList:             audienceList,
		idpSignkeyRefreshEnabled: true,
		keyFetcher:               keyFetcher,
	}
}

// forcedRefreshCooldown is the minimum time between forced key refreshes
// to prevent abuse from invalid tokens with fake kid values
const forcedRefreshCooldown = 30 * time.Second

// fetchKeys retrieves keys using the keyFetcher if available, otherwise falls back to HTTP.
func (v *Validator) fetchKeys(ctx context.Context) (*Jwks, error) {
	if v.keyFetcher != nil {
		return v.keyFetcher(ctx)
	}
	return getPemKeys(v.keysLocation)
}

func (v *Validator) getKeyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// If keys are rotated, verify the keys prior to token validation
		if v.idpSignkeyRefreshEnabled {
			// If the keys are invalid, retrieve new ones
			if !v.keys.stillValid() {
				v.refreshKeys(ctx)
			}
		}

		publicKey, err := getPublicKey(token, v.keys)
		if err == nil {
			return publicKey, nil
		}

		// If key not found and refresh is enabled, try refreshing keys and retry once.
		// This handles the case where keys were rotated but cache hasn't expired yet.
		// Use a cooldown to prevent abuse from tokens with fake kid values.
		if errors.Is(err, errKeyNotFound) && v.idpSignkeyRefreshEnabled {
			if v.forceRefreshKeys(ctx) {
				publicKey, err = getPublicKey(token, v.keys)
				if err == nil {
					return publicKey, nil
				}
			}
		}

		msg := fmt.Sprintf("getPublicKey error: %s", err)
		if errors.Is(err, errKeyNotFound) && !v.idpSignkeyRefreshEnabled {
			msg = fmt.Sprintf("getPublicKey error: %s. You can enable key refresh by setting HttpServerConfig.IdpSignKeyRefreshEnabled to true in your management.json file and restart the service", err)
		}

		log.WithContext(ctx).Error(msg)

		return nil, err
	}
}

func (v *Validator) refreshKeys(ctx context.Context) {
	v.lock.Lock()
	defer v.lock.Unlock()

	refreshedKeys, err := v.fetchKeys(ctx)
	if err != nil {
		log.WithContext(ctx).Debugf("cannot get JSONWebKey: %v, falling back to old keys", err)
		return
	}

	log.WithContext(ctx).Debugf("keys refreshed, new UTC expiration time: %s", refreshedKeys.ExpiresInTime.UTC())
	v.keys = refreshedKeys
}

// forceRefreshKeys refreshes keys if the cooldown period has passed.
// Returns true if keys were refreshed, false if cooldown prevented refresh.
// The cooldown check is done inside the lock to prevent race conditions.
func (v *Validator) forceRefreshKeys(ctx context.Context) bool {
	v.lock.Lock()
	defer v.lock.Unlock()

	// Check cooldown inside lock to prevent multiple goroutines from refreshing
	if time.Since(v.lastForcedRefresh) <= forcedRefreshCooldown {
		return false
	}

	log.WithContext(ctx).Debugf("key not found in cache, forcing JWKS refresh")

	refreshedKeys, err := v.fetchKeys(ctx)
	if err != nil {
		log.WithContext(ctx).Debugf("cannot get JSONWebKey: %v, falling back to old keys", err)
		return false
	}

	log.WithContext(ctx).Debugf("keys refreshed, new UTC expiration time: %s", refreshedKeys.ExpiresInTime.UTC())
	v.keys = refreshedKeys
	v.lastForcedRefresh = time.Now()
	return true
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
	parsedToken, err := jwt.Parse(
		token,
		v.getKeyFunc(ctx),
		jwt.WithAudience(v.audienceList...),
		jwt.WithIssuer(v.issuer),
		jwt.WithIssuedAt(),
	)

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
	return !jwks.ExpiresInTime.IsZero() && time.Now().Add(5*time.Second).Before(jwks.ExpiresInTime)
}

func getPemKeys(keysLocation string) (*Jwks, error) {
	jwks := &Jwks{}

	requestURI, err := url.ParseRequestURI(keysLocation)
	if err != nil {
		return jwks, err
	}

	resp, err := http.Get(requestURI.String())
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
	jwks.ExpiresInTime = time.Now().Add(time.Duration(expiresIn) * time.Second)

	return jwks, nil
}

func isSupportedECCurve(crv string) bool {
	switch crv {
	case "P-256", "P-384", "P-521":
		return true
	default:
		return false
	}
}

 func getPublicKeyForEC(jwk JSONWebKey) (interface{}, error) {
	// For EC, prefer x, y, crv fields if present and curve is supported
	if jwk.X != "" && jwk.Y != "" && jwk.Crv != "" {
		// Validate curve is supported before calling getPublicKeyFromECDSA
		if !isSupportedECCurve(jwk.Crv) {
			return nil, fmt.Errorf("unsupported EC curve: %s (kid: %s)", jwk.Crv, jwk.Kid)
		}
		return getPublicKeyFromECDSA(jwk)
	}
 
	// Fallback to x5c if x/y/crv are missing
	if len(jwk.X5c) != 0 {
		return parseECKeyFromCertificate(jwk)
	}
 
	// Neither x/y/crv nor x5c available
	return nil, fmt.Errorf("EC key incomplete: missing both x/y/crv fields and x5c certificate (kid: %s)", jwk.Kid)
}

func getPublicKey(token *jwt.Token, jwks *Jwks) (interface{}, error) {
	// todo as we load the jkws when the server is starting, we should build a JKS map with the pem cert at the boot time
	for k := range jwks.Keys {
		if token.Header["kid"] != jwks.Keys[k].Kid {
			continue
		}
 
		// Key with matching kid found - check type
		switch jwks.Keys[k].Kty {
		case "RSA":
			// For RSA, prefer x5c certificate if available
			if len(jwks.Keys[k].X5c) != 0 {
				cert := "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
				return jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			}
			return getPublicKeyFromRSA(jwks.Keys[k])
 
		case "EC":
			return getPublicKeyForEC(jwks.Keys[k])
 
		default:
			// Key type not supported
			return nil, fmt.Errorf("%w: %s (kid: %s)", errUnsupportedKeyType, jwks.Keys[k].Kty, jwks.Keys[k].Kid)
		}
	}
 
	// No key with matching kid found
	return nil, errKeyNotFound
}


// parseECKeyFromCertificate extracts EC public key from x5c certificate
func parseECKeyFromCertificate(jwk JSONWebKey) (*ecdsa.PublicKey, error) {
	cert := "-----BEGIN CERTIFICATE-----\n" + jwk.X5c[0] + "\n-----END CERTIFICATE-----"
 
	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate for EC key (kid: %s)", jwk.Kid)
	}
 
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x5c certificate for EC key (kid: %s): %w", jwk.Kid, err)
	}
 
	ecKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("x5c certificate does not contain EC public key (kid: %s)", jwk.Kid)
	}
 
	return ecKey, nil
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
