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

func SignToken(privKeyB64, userID, domain string, method auth.Method, expiration time.Duration) (string, error) {
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
		Method: method,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signedToken, err := token.SignedString(privKey)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signedToken, nil
}
