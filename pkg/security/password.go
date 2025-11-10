package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/argon2"
)

var (
	// ErrInvalidHash is returned when the encoded hash is not in the correct format
	ErrInvalidHash = errors.New("the encoded hash is not in the correct format")
	// ErrIncompatibleVersion is returned when the argon2 version is not compatible
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
)

// Argon2Config holds the configuration for Argon2 hashing
// These values should be tuned based on your security requirements and hardware
var DefaultArgon2Config = &Argon2Config{
	Time:    3,
	Memory:  64 * 1024, // 64MB
	Threads: 4,
	KeyLen:  32,
	SaltLen: 16,
}

// Argon2Config holds the configuration for Argon2 hashing
type Argon2Config struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32
}

// HashPassword hashes a password using Argon2id
func HashPassword(password string, config *Argon2Config) (string, error) {
	if config == nil {
		config = DefaultArgon2Config
	}

	// Generate a cryptographically secure random salt
	salt := make([]byte, config.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate the hash using Argon2id
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		config.Time,
		config.Memory,
		config.Threads,
		config.KeyLen,
	)

	// Encode the hash and salt for storage
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		config.Memory,
		config.Time,
		config.Threads,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

// VerifyPassword verifies a password against a hashed value
func VerifyPassword(password, encodedHash string) (bool, error) {
	// Parse the encoded hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, ErrInvalidHash
	}

	// Check the algorithm
	if parts[1] != "argon2id" {
		return false, fmt.Errorf("unsupported algorithm: %s", parts[1])
	}

	// Parse version
	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil || version != argon2.Version {
		return false, ErrIncompatibleVersion
	}

	// Parse parameters
	var memory, iterations uint32
	var threads uint8
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &threads)
	if err != nil {
		return false, fmt.Errorf("invalid parameter format: %w", err)
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	// Generate the comparison hash
	comparisonHash := argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		threads,
		uint32(len(hash)),
	)

	// Constant time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(hash, comparisonHash) == 1, nil
}

// PasswordPolicy defines the password policy requirements
type PasswordPolicy struct {
	MinLength     int
	RequireUpper  bool
	RequireLower  bool
	RequireNumber bool
	RequireSymbol bool
}

// DefaultPasswordPolicy returns a sensible default password policy
func DefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:     12,
		RequireUpper:  true,
		RequireLower:  true,
		RequireNumber: true,
		RequireSymbol: true,
	}
}

// ValidatePassword checks if a password meets the policy requirements
func ValidatePassword(password string, policy *PasswordPolicy) error {
	if policy == nil {
		policy = DefaultPasswordPolicy()
	}

	// Check minimum length
	if len(password) < policy.MinLength {
		return fmt.Errorf("password must be at least %d characters long", policy.MinLength)
	}

	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSymbol  = false
		totalChars = 0
	)

	// Check for required character types
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSymbol = true
		}
		totalChars++
	}

	// Check requirements
	var missingRequirements []string

	if policy.RequireUpper && !hasUpper {
		missingRequirements = append(missingRequirements, "uppercase letter")
	}

	if policy.RequireLower && !hasLower {
		missingRequirements = append(missingRequirements, "lowercase letter")
	}

	if policy.RequireNumber && !hasNumber {
		missingRequirements = append(missingRequirements, "number")
	}

	if policy.RequireSymbol && !hasSymbol {
		missingRequirements = append(missingRequirements, "symbol")
	}

	if len(missingRequirements) > 0 {
		return fmt.Errorf("password must contain at least one %s", strings.Join(missingRequirements, ", "))
	}

	// Check for common passwords (simplified example)
	if isCommonPassword(password) {
		return errors.New("password is too common or easily guessable")
	}

	return nil
}

// isCommonPassword checks if the password is in a list of common passwords
// This is a simplified example - in production, use a larger dictionary
func isCommonPassword(password string) bool {
	commonPasswords := map[string]bool{
		"password":          true,
		"123456":            true,
		"qwerty":            true,
		"letmein":           true,
		"admin":             true,
		"welcome":           true,
		"password1":         true,
		"12345678":          true,
		"123456789":         true,
		"123123":            true,
		"111111":            true,
		"sunshine":          true,
		"iloveyou":          true,
		"admin123":          true,
		"welcome1":          true,
		"monkey":            true,
		"1234567":           true,
		"1234567890":        true,
		"admin1234":         true,
		"dragon":            true,
		"password123":       true,
		"master":            true,
		"hello":             true,
		"solo":              true,
		"princess":          true,
		"qwertyuiop":        true,
		"qwerty123":         true,
		"login":             true,
		"passw0rd":          true,
		"admin1":            true,
		"welcome123":        true,
		"football":          true,
		"12345":             true,
		"1234":              true,
		"123":               true,
		"12345678910":       true,
		"michael":           true,
		"654321":            true,
		"superman":          true,
		"1qaz2wsx":          true,
		"baseball":          true,
		"qazwsxedc":         true,
		"password!":         true,
		"password1!":        true,
		"Password1":         true,
		"Password123":       true,
		"Password!":         true,
		"Admin123":          true,
		"Admin123!":         true,
		"Admin123#":         true,
		"Admin@123":         true,
		"Admin#123":         true,
		"Admin$123":         true,
		"Admin%123":         true,
		"Admin^123":         true,
		"Admin&123":         true,
		"Admin*123":         true,
		"Admin(123":         true,
		"Admin)123":         true,
		"Admin-123":         true,
		"Admin_123":         true,
		"Admin+123":         true,
		"Admin=123":         true,
		"Admin{123":         true,
		"Admin}123":         true,
		"Admin[123":         true,
		"Admin]123":         true,
		"Admin\\123":        true,
		"Admin|123":         true,
		"Admin;123":         true,
		"Admin:123":         true,
		"Admin'123":         true,
		"Admin\"123":        true,
		"Admin<123":         true,
		"Admin>123":         true,
		"Admin,123":         true,
		"Admin.123":         true,
		"Admin/123":         true,
		"Admin?123":         true,
		"Admin`123":         true,
		"Admin~123":         true,
		"Admin!123":         true,
		"Admin@1234":        true,
		"Admin#1234":        true,
		"Admin$1234":        true,
		"Admin%1234":        true,
		"Admin^1234":        true,
		"Admin&1234":        true,
		"Admin*1234":        true,
		"Admin(1234":        true,
		"Admin)1234":        true,
		"Admin-1234":        true,
		"Admin_1234":        true,
		"Admin+1234":        true,
		"Admin=1234":        true,
		"Admin{1234":        true,
		"Admin}1234":        true,
		"Admin[1234":        true,
		"Admin]1234":        true,
		"Admin\\1234":       true,
		"Admin|1234":        true,
		"Admin;1234":        true,
		"Admin:1234":        true,
		"Admin'1234":        true,
		"Admin\"1234":       true,
		"Admin<1234":        true,
		"Admin>1234":        true,
		"Admin,1234":        true,
		"Admin.1234":        true,
		"Admin/1234":        true,
		"Admin?1234":        true,
		"Admin`1234":        true,
		"Admin~1234":        true,
		"Admin!1234":        true,
	}

	// Check against common passwords
	if commonPasswords[strings.ToLower(password)] {
		return true
	}

	// Check for sequential characters (e.g., 123456, abcdef)
	if isSequential(password) {
		return true
	}

	// Check for repeated characters (e.g., aaaaaa, 111111)
	if isRepeated(password) {
		return true
	}

	return false
}

// isSequential checks if the password contains sequential characters
func isSequential(password string) bool {
	if len(password) < 3 {
		return false
	}

	// Check for sequential numbers (e.g., 12345, 98765)
	isSequential := true
	for i := 1; i < len(password); i++ {
		if password[i] != password[i-1]+1 {
			isSequential = false
			break
		}
	}

	if isSequential {
		return true
	}

	// Check for reverse sequential numbers (e.g., 54321)
	isReverseSequential := true
	for i := 1; i < len(password); i++ {
		if password[i] != password[i-1]-1 {
			isReverseSequential = false
			break
		}
	}

	return isReverseSequential
}

// isRepeated checks if the password contains repeated characters
func isRepeated(password string) bool {
	if len(password) < 3 {
		return false
	}

	firstChar := password[0]
	for i := 1; i < len(password); i++ {
		if password[i] != firstChar {
			return false
		}
	}

	return true
}

// GenerateRandomPassword generates a random password that meets the policy requirements
func GenerateRandomPassword(length int, policy *PasswordPolicy) (string, error) {
	if policy == nil {
		policy = DefaultPasswordPolicy()
	}

	if length < policy.MinLength {
		length = policy.MinLength
	}

	// Define character sets
	lowercase := "abcdefghijklmnopqrstuvwxyz"
	uppercase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits := "0123456789"
	symbols := "!@#$%^&*()-_=+[]{}|;:,.<>/?"

	// Build the character set based on policy
	var chars string

	// Always include at least one of each required character type
	var password []byte
	var charSet string

	// Add required characters first
	if policy.RequireLower {
		charSet += lowercase
		password = append(password, lowercase[randomInt(0, len(lowercase))])
	}

	if policy.RequireUpper {
		charSet += uppercase
		password = append(password, uppercase[randomInt(0, len(uppercase))])
	}

	if policy.RequireNumber {
		charSet += digits
		password = append(password, digits[randomInt(0, len(digits))])
	}

	if policy.RequireSymbol {
		charSet += symbols
		password = append(password, symbols[randomInt(0, len(symbols))])
	}

	// If no policy requirements, use all character sets
	if charSet == "" {
		charSet = lowercase + uppercase + digits + symbols
	}

	// Fill the rest of the password with random characters from the combined set
	for len(password) < length {
		password = append(password, charSet[randomInt(0, len(charSet))])
	}

	// Shuffle the password to ensure randomness
	shuffleBytes(password)

	// Convert to string and validate
	result := string(password)
	if err := ValidatePassword(result, policy); err != nil {
		logrus.WithError(err).Warn("Generated password failed validation, retrying...")
		return GenerateRandomPassword(length, policy)
	}

	return result, nil
}

// randomInt returns a random integer in the range [min, max)
func randomInt(min, max int) int {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		panic(err) // This should never happen with crypto/rand
	}

	r := int(buf[0])<<56 | int(buf[1])<<48 | int(buf[2])<<40 | int(buf[3])<<32 |
		int(buf[4])<<24 | int(buf[5])<<16 | int(buf[6])<<8 | int(buf[7])

	if min == max {
		return min
	}

	if min > max {
		min, max = max, min
	}

	return min + (r % (max - min))
}

// shuffleBytes shuffles a byte slice in place
func shuffleBytes(b []byte) {
	for i := range b {
		j := randomInt(i, len(b))
		b[i], b[j] = b[j], b[i]
	}
}
