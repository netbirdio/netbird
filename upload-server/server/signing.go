package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	signingKeyVar = "NB_UPLOAD_SIGNING_KEY"

	// signatureTTL matches the expiry the S3 backend puts on its presigned URLs.
	signatureTTL = 15 * time.Minute

	expiryParam    = "exp"
	signatureParam = "sig"
)

type signer struct {
	key []byte
}

func newSigner() (*signer, error) {
	if env, ok := os.LookupEnv(signingKeyVar); ok {
		if env == "" {
			return nil, fmt.Errorf("%s is set but empty", signingKeyVar)
		}
		return &signer{key: []byte(env)}, nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	log.Infof("%s not set, generated an ephemeral upload signing key", signingKeyVar)

	return &signer{key: key}, nil
}

// sign returns the query parameters that authorize an upload of objectKey.
func (s *signer) sign(objectKey string, now time.Time) url.Values {
	exp := now.Add(signatureTTL).Unix()

	v := url.Values{}
	v.Set(expiryParam, strconv.FormatInt(exp, 10))
	v.Set(signatureParam, hex.EncodeToString(s.signature(objectKey, exp)))

	return v
}

// verify reports whether query carries a still-valid signature over objectKey.
func (s *signer) verify(objectKey string, query url.Values, now time.Time) error {
	exp, err := strconv.ParseInt(query.Get(expiryParam), 10, 64)
	if err != nil {
		return fmt.Errorf("malformed %s parameter", expiryParam)
	}

	got, err := hex.DecodeString(query.Get(signatureParam))
	if err != nil {
		return fmt.Errorf("malformed %s parameter", signatureParam)
	}

	if !hmac.Equal(got, s.signature(objectKey, exp)) {
		return fmt.Errorf("signature mismatch")
	}
	if now.Unix() > exp {
		return fmt.Errorf("upload URL expired")
	}

	return nil
}

func (s *signer) signature(objectKey string, exp int64) []byte {
	mac := hmac.New(sha256.New, s.key)
	fmt.Fprintf(mac, "%s\n%d", objectKey, exp)
	return mac.Sum(nil)
}
