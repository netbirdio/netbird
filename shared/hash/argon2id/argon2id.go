package argon2id

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2Memory      = 19456
	argon2Iterations  = 2
	argon2Parallelism = 1
	argon2SaltLength  = 16
	argon2KeyLength   = 32
)

var (
	// ErrInvalidHash is returned when the hash string format is invalid
	ErrInvalidHash = errors.New("invalid hash format")

	// ErrIncompatibleVersion is returned when the Argon2 version is not supported
	ErrIncompatibleVersion = errors.New("incompatible argon2 version")

	// ErrMismatchedHashAndPassword is returned when password verification fails
	ErrMismatchedHashAndPassword = errors.New("password does not match hash")
)

func Hash(secret string) (string, error) {
	salt := make([]byte, argon2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(secret),
		salt,
		argon2Iterations,
		argon2Memory,
		argon2Parallelism,
		argon2KeyLength,
	)

	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2Memory,
		argon2Iterations,
		argon2Parallelism,
		encodedSalt,
		encodedHash,
	), nil
}

func Verify(secret, encodedHash string) error {
	params, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return err
	}

	computedHash := argon2.IDKey(
		[]byte(secret),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		params.keyLength,
	)

	if subtle.ConstantTimeCompare(hash, computedHash) == 1 {
		return nil
	}

	return ErrMismatchedHashAndPassword
}

type hashParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLength   uint32
	version     int
}

func decodeHash(encodedHash string) (*hashParams, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")

	if len(parts) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: invalid version: %v", ErrInvalidHash, err)
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: invalid parameters: %v", ErrInvalidHash, err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: invalid salt encoding: %v", ErrInvalidHash, err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: invalid hash encoding: %v", ErrInvalidHash, err)
	}

	params := &hashParams{
		memory:      memory,
		iterations:  iterations,
		parallelism: parallelism,
		keyLength:   uint32(len(hash)),
		version:     version,
	}

	return params, salt, hash, nil
}
