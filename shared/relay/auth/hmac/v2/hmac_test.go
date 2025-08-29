package v2

import (
	"strconv"
	"testing"
	"time"
)

func TestGenerateCredentials(t *testing.T) {
	secret := "supersecret"
	timeToLive := 1 * time.Hour
	g, err := NewGenerator(AuthAlgoHMACSHA256, []byte(secret), timeToLive)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	token, err := g.GenerateToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(token.Payload) == 0 {
		t.Fatalf("expected non-empty payload")
	}

	_, err = strconv.ParseInt(string(token.Payload), 10, 64)
	if err != nil {
		t.Fatalf("expected payload to be a valid unix timestamp, got %v", err)
	}
}

func TestValidateCredentials(t *testing.T) {
	secret := "supersecret"
	timeToLive := 1 * time.Hour
	g, err := NewGenerator(AuthAlgoHMACSHA256, []byte(secret), timeToLive)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	token, err := g.GenerateToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	v := NewValidator([]byte(secret))
	if err := v.Validate(token.Marshal()); err != nil {
		t.Fatalf("expected valid token: %s", err)
	}
}

func TestInvalidSignature(t *testing.T) {
	secret := "supersecret"
	timeToLive := 1 * time.Hour
	g, err := NewGenerator(AuthAlgoHMACSHA256, []byte(secret), timeToLive)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	token, err := g.GenerateToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	token.Signature = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	v := NewValidator([]byte(secret))
	if err := v.Validate(token.Marshal()); err == nil {
		t.Fatalf("expected valid token: %s", err)
	}
}

func TestExpired(t *testing.T) {
	secret := "supersecret"
	timeToLive := -1 * time.Hour
	g, err := NewGenerator(AuthAlgoHMACSHA256, []byte(secret), timeToLive)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	token, err := g.GenerateToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	v := NewValidator([]byte(secret))
	if err := v.Validate(token.Marshal()); err == nil {
		t.Fatalf("expected valid token: %s", err)
	}
}

func TestInvalidPayload(t *testing.T) {
	secret := "supersecret"
	timeToLive := 1 * time.Hour
	g, err := NewGenerator(AuthAlgoHMACSHA256, []byte(secret), timeToLive)
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	token, err := g.GenerateToken()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	token.Payload = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	v := NewValidator([]byte(secret))
	if err := v.Validate(token.Marshal()); err == nil {
		t.Fatalf("expected invalid token due to invalid payload")
	}
}
