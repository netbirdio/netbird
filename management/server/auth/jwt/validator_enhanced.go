package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// EnhancedValidator provides enhanced JWT validation with security best practices
type EnhancedValidator struct {
	issuer                   string
	audienceList             []string
	keysLocation             string
	idpSignkeyRefreshEnabled bool
	keys                     *Jwks
	lock                     sync.RWMutex
	client                   *http.Client
}

// NewEnhancedValidator creates a new instance of EnhancedValidator
func NewEnhancedValidator(issuer string, audienceList []string, keysLocation string, idpSignkeyRefreshEnabled bool) *EnhancedValidator {
	return &EnhancedValidator{
		issuer:                   issuer,
		audienceList:             audienceList,
		keysLocation:             keysLocation,
		idpSignkeyRefreshEnabled: idpSignkeyRefreshEnabled,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ValidateToken validates the JWT token with enhanced security checks
func (v *EnhancedValidator) ValidateToken(ctx context.Context, tokenString string) (*jwt.Token, error) {
	// Parse with validation of algorithm
	token, err := jwt.Parse(tokenString, v.getKeyFunc(ctx),
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audienceList...),
	)

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Additional claims validation
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		// Check token expiration with leeway
		exp, err := claims.GetExpirationTime()
		if err != nil || exp == nil || exp.Before(time.Now().Add(-10*time.Second)) {
			return nil, errors.New("token is expired")
		}

		// Check not before time
		if nbf, err := claims.GetNotBefore(); err == nil && nbf != nil {
			if nbf.After(time.Now().Add(10 * time.Second)) {
				return nil, errors.New("token not valid yet")
			}
		}

		// Check issued at time
		if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
			if iat.After(time.Now().Add(10 * time.Second)) {
				return nil, errors.New("token issued in the future")
			}
		}

		// Check token type if present
		if typ, ok := claims["typ"].(string); ok && !strings.EqualFold(typ, "JWT") {
			return nil, errors.New("invalid token type")
		}

		// Check token scope if present
		if scope, ok := claims["scope"].(string); ok {
			if !v.validateScope(scope) {
				return nil, errors.New("insufficient scope")
			}
		}

		// Log security-relevant token claims
		logrus.WithFields(logrus.Fields{
			"issuer":    claims["iss"],
			"subject":   claims["sub"],
			"audience":  claims["aud"],
			"expiresAt": claims["exp"],
			"issuedAt":  claims["iat"],
		}).Debug("JWT token validated successfully")
	}

	return token, nil
}

// validateScope checks if the token has the required scope
func (v *EnhancedValidator) validateScope(scope string) bool {
	// Implement scope validation logic here
	// For example, check if the token has required scopes
	return true
}

// getKeyFunc returns a function that provides the key for token verification
func (v *EnhancedValidator) getKeyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// If keys are rotated, verify the keys prior to token validation
		if v.idpSignkeyRefreshEnabled && (v.keys == nil || !v.keys.stillValid()) {
			if err := v.refreshKeys(ctx); err != nil {
				logrus.WithError(err).Warn("Failed to refresh keys, using cached keys")
			}
		}

		if v.keys == nil {
			return nil, errors.New("no keys available for validation")
		}

		// Get the key ID from the token header
		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("token missing key ID (kid) in header")
		}

		// Find the key with the matching key ID
		for _, key := range v.keys.Keys {
			if key.Kid == keyID {
				switch key.Kty {
				case "RSA":
					return key.getRSAPublicKey()
				case "EC":
					return key.getECDSAPublicKey()
				default:
					return nil, fmt.Errorf("unsupported key type: %s", key.Kty)
			}
		}

		return nil, errors.New("key not found for token")
	}
}

// refreshKeys fetches the latest keys from the keys location
func (v *EnhancedValidator) refreshKeys(ctx context.Context) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.keysLocation, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add cache control headers to prevent caching
	req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Expires", "0")

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var keys Jwks
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return fmt.Errorf("failed to decode keys: %w", err)
	}

	// Set expiration time for the keys (default to 1 hour if not specified in cache headers)
	expiresIn := 1 * time.Hour
	if cacheControl := resp.Header.Get("Cache-Control"); cacheControl != "" {
		if maxAge := getMaxAgeFromCacheHeader(cacheControl); maxAge > 0 {
			expiresIn = time.Duration(maxAge) * time.Second
		}
	}

	keys.expiresInTime = time.Now().Add(expiresIn)
	v.keys = &keys

	logrus.WithField("keys_count", len(keys.Keys)).Info("Successfully refreshed JWT keys")
	return nil
}
