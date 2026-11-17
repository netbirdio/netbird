package sessionkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/netbirdio/netbird/proxy/auth"
)

type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

type Claims struct {
	jwt.RegisteredClaims
	Method auth.Method `json:"method"`
	// Email is the calling user's email address. Carried so the
	// proxy can stamp identity on upstream requests (e.g.
	// x-litellm-end-user-id) without an extra management
	// round-trip on every cookie-bearing request.
	Email string `json:"email,omitempty"`
	// Groups carries the user's group IDs so the proxy can stamp them
	// onto upstream requests (X-NetBird-Groups) from the cookie path
	// without an extra management round-trip.
	Groups []string `json:"groups,omitempty"`
	// GroupNames carries the human-readable display names for the ids
	// in Groups, ordered identically (positional pairing). Slice may be
	// shorter than Groups for tokens minted before names were
	// resolvable; the consumer falls back to ids for missing positions.
	GroupNames []string `json:"group_names,omitempty"`
}

func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	return &KeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

// SignToken mints a session JWT for the given user and domain. email,
// groups, and groupNames, when non-empty, are embedded so the proxy can
// authorise and stamp identity for policy-aware middlewares without a
// management round-trip on every cookie-bearing request. groupNames
// pairs positionally with groups; pass nil when names couldn't be
// resolved.
func SignToken(privKeyB64, userID, email, domain string, method auth.Method, groups, groupNames []string, expiration time.Duration) (string, error) {
	privKeyBytes, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}

	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("invalid private key size: got %d, want %d", len(privKeyBytes), ed25519.PrivateKeySize)
	}

	privKey := ed25519.PrivateKey(privKeyBytes)

	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    auth.SessionJWTIssuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{domain},
			ExpiresAt: jwt.NewNumericDate(now.Add(expiration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		Method:     method,
		Email:      email,
		Groups:     append([]string(nil), groups...),
		GroupNames: append([]string(nil), groupNames...),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signedToken, err := token.SignedString(privKey)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signedToken, nil
}
