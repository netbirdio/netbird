package sqlite

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestRestoreKey(t *testing.T) {
	_, err := RestoreKey(t.TempDir())
	if err != nil {
		log.Infof("err: %s", err)
	}
}

func TestGenerateKey(t *testing.T) {
	testData := "exampl@netbird.io"
	key, err := GenerateKey(t.TempDir())
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}
	ee, err := NewFieldEncrypt(key)
	if err != nil {
		t.Fatalf("failed to init email encryption: %s", err)
	}

	encrypted := ee.Encrypt(testData)
	if encrypted == "" {
		t.Fatalf("invalid encrypted text")
	}

	decrypted, err := ee.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("failed to decrypt data: %s", err)
	}

	if decrypted != testData {
		t.Fatalf("decrypted data is not match with test data: %s, %s", testData, decrypted)
	}
}

func TestCorruptKey(t *testing.T) {
	testData := "exampl@netbird.io"
	key, err := GenerateKey(t.TempDir())
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}
	ee, err := NewFieldEncrypt(key)
	if err != nil {
		t.Fatalf("failed to init email encryption: %s", err)
	}

	encrypted := ee.Encrypt(testData)
	if encrypted == "" {
		t.Fatalf("invalid encrypted text")
	}

	newKey, err := GenerateKey(t.TempDir())
	if err != nil {
		t.Fatalf("failed to generate key: %s", err)
	}

	ee, err = NewFieldEncrypt(newKey)
	if err != nil {
		t.Fatalf("failed to init email encryption: %s", err)
	}

	res, _ := ee.Decrypt(encrypted)
	if res == testData {
		t.Fatalf("incorrect decryption, the result is: %s", res)
	}
}
