package hmac

import (
	"crypto/sha1"
	"encoding/base64"
	"strconv"
	"testing"
	"time"
)

func TestGenerateCredentials(t *testing.T) {
	secret := "secret"
	timeToLive := 1 * time.Hour
	v := NewTimedHMAC(secret, timeToLive)

	creds, err := v.GenerateToken(sha1.New)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if creds.Payload == "" {
		t.Fatalf("expected non-empty payload")
	}

	_, err = strconv.ParseInt(creds.Payload, 10, 64)
	if err != nil {
		t.Fatalf("expected payload to be a valid unix timestamp, got %v", err)
	}

	_, err = base64.StdEncoding.DecodeString(creds.Signature)
	if err != nil {
		t.Fatalf("expected signature to be base64 encoded, got %v", err)
	}
}
