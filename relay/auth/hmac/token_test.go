package hmac

import (
	"crypto/sha1"
	"crypto/sha256"
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

func TestValidateCredentials(t *testing.T) {
	secret := "supersecret"
	timeToLive := 1 * time.Hour
	manager := NewTimedHMAC(secret, timeToLive)

	// Test valid token
	creds, err := manager.GenerateToken(sha1.New)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if err := manager.Validate(sha1.New, *creds); err != nil {
		t.Fatalf("expected valid token: %s", err)
	}
}

func TestInvalidSignature(t *testing.T) {
	secret := "supersecret"
	timeToLive := 1 * time.Hour
	manager := NewTimedHMAC(secret, timeToLive)

	creds, err := manager.GenerateToken(sha256.New)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	invalidCreds := &Token{
		Payload:   creds.Payload,
		Signature: "invalidsignature",
	}

	if err = manager.Validate(sha1.New, *invalidCreds); err == nil {
		t.Fatalf("expected invalid token due to signature mismatch")
	}
}

func TestExpired(t *testing.T) {
	secret := "supersecret"
	v := NewTimedHMAC(secret, -1*time.Hour)
	expiredCreds, err := v.GenerateToken(sha256.New)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if err = v.Validate(sha1.New, *expiredCreds); err == nil {
		t.Fatalf("expected invalid token due to expiration")
	}
}

func TestInvalidPayload(t *testing.T) {
	secret := "supersecret"
	timeToLive := 1 * time.Hour
	v := NewTimedHMAC(secret, timeToLive)

	creds, err := v.GenerateToken(sha256.New)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Test invalid payload
	invalidPayloadCreds := &Token{
		Payload:   "invalidtimestamp",
		Signature: creds.Signature,
	}

	if err = v.Validate(sha1.New, *invalidPayloadCreds); err == nil {
		t.Fatalf("expected invalid token due to invalid payload")
	}
}
