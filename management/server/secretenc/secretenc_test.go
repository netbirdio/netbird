package secretenc_test

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/netbirdio/netbird/management/server/secretenc"
)

var testKey32 = [32]byte{
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
}
var testKeyB64 = base64.StdEncoding.EncodeToString(testKey32[:])

func TestEnvKeyProvider_RoundTrip(t *testing.T) {
	t.Setenv("TEST_SECRET_KEY", testKeyB64)
	kp, err := secretenc.NewEnvKeyProvider("TEST_SECRET_KEY")
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("hello secret")
	ct, err := kp.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := kp.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("got %q want %q", got, plain)
	}
}

func TestEnvKeyProvider_MissingVar_ReturnsError(t *testing.T) {
	_, err := secretenc.NewEnvKeyProvider("NONEXISTENT_VAR_XYZ_789")
	if err == nil {
		t.Fatal("expected error for missing env var")
	}
}

func TestNoOpKeyProvider_RoundTrip(t *testing.T) {
	kp := secretenc.NewNoOpKeyProvider()
	plain := []byte("plain text")
	ct, err := kp.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := kp.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("got %q want %q", got, plain)
	}
}

func TestFileKeyProvider_RoundTrip(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "key")
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32) // 32 zero bytes
	if _, err := f.Write(key); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Chmod(f.Name(), 0600); err != nil {
		t.Fatal(err)
	}

	kp, err := secretenc.NewFileKeyProvider(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("my secret")
	ct, err := kp.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := kp.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("got %q want %q", got, plain)
	}
}

func TestAESGCM_DifferentNonceEachEncrypt(t *testing.T) {
	t.Setenv("TEST_SECRET_KEY2", testKeyB64)
	kp, err := secretenc.NewEnvKeyProvider("TEST_SECRET_KEY2")
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("same input")
	ct1, err := kp.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := kp.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(ct1) == string(ct2) {
		t.Fatal("expected different ciphertext each time (random nonce)")
	}
}

func TestDecrypt_TamperedCiphertext_ReturnsError(t *testing.T) {
	t.Setenv("TEST_SECRET_KEY3", testKeyB64)
	kp, err := secretenc.NewEnvKeyProvider("TEST_SECRET_KEY3")
	if err != nil {
		t.Fatal(err)
	}
	ct, err := kp.Encrypt([]byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	ct[len(ct)-1] ^= 0xFF // flip last byte (auth tag)
	_, err = kp.Decrypt(ct)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestEnvKeyProvider_WrongKeyLength_ReturnsError(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	t.Setenv("TEST_SHORT_KEY", short)
	_, err := secretenc.NewEnvKeyProvider("TEST_SHORT_KEY")
	if err == nil {
		t.Fatal("expected error for 16-byte key")
	}
}

func TestDecrypt_TooShortCiphertext_ReturnsError(t *testing.T) {
	t.Setenv("TEST_SECRET_KEY4", testKeyB64)
	kp, err := secretenc.NewEnvKeyProvider("TEST_SECRET_KEY4")
	if err != nil {
		t.Fatal(err)
	}
	_, err = kp.Decrypt([]byte("short"))
	if err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}
