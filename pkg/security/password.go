package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
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

// DefaultArgon2Config provides a secure default configuration for Argon2 password hashing.
// These values are tuned for a balance between security and performance on modern hardware.
//
// Configuration:
//   - Time: 3 iterations (higher = more secure but slower)
//   - Memory: 64MB (higher = more secure but requires more RAM)
//   - Threads: 4 parallel threads (should match CPU cores)
//   - KeyLen: 32 bytes (256 bits) for the hash output
//   - SaltLen: 16 bytes (128 bits) for the salt
//
// For production use, consider tuning these values based on your security requirements
// and hardware capabilities. Higher values provide better security but increase computation time.
var DefaultArgon2Config = &Argon2Config{
	Time:    3,
	Memory:  64 * 1024, // 64MB
	Threads: 4,
	KeyLen:  32,
	SaltLen: 16,
}

// Argon2Config holds the configuration parameters for Argon2 password hashing.
// Argon2 is a memory-hard password hashing function that provides resistance against
// both GPU and ASIC attacks.
//
// Fields:
//   - Time: Number of iterations (higher = more secure but slower)
//   - Memory: Memory cost in KB (higher = more secure but requires more RAM)
//   - Threads: Number of parallel threads (should match available CPU cores)
//   - KeyLen: Length of the generated hash in bytes (typically 32 for 256 bits)
//   - SaltLen: Length of the salt in bytes (typically 16 for 128 bits)
type Argon2Config struct {
	Time    uint32 // Number of iterations
	Memory  uint32 // Memory cost in KB
	Threads uint8  // Number of parallel threads
	KeyLen  uint32 // Length of hash output in bytes
	SaltLen uint32 // Length of salt in bytes
}

// HashPassword hashes a password using Argon2id, which is the recommended variant
// of Argon2 for password hashing. It provides a balance between resistance to
// side-channel attacks and GPU cracking attacks.
//
// The function generates a cryptographically secure random salt and combines it
// with the password to create a hash. The result is encoded in a format that
// includes all parameters needed for verification.
//
// Parameters:
//   - password: The plaintext password to hash
//   - config: Argon2 configuration parameters. If nil, DefaultArgon2Config is used.
//
// Returns:
//   - A string containing the encoded hash in format: $argon2id$v=VERSION$m=MEMORY,t=TIME,p=THREADS$SALT$HASH
//   - An error if salt generation or hashing fails
//
// Security: The password is never logged or exposed. The hash can be safely stored
// in a database. Use VerifyPassword to check passwords against the hash.
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

// VerifyPassword verifies a password against a previously hashed value.
// It uses constant-time comparison to prevent timing attacks.
//
// Parameters:
//   - password: The plaintext password to verify
//   - encodedHash: The encoded hash string from HashPassword
//
// Returns:
//   - true if the password matches the hash
//   - false if the password does not match
//   - An error if the hash format is invalid or incompatible
//
// Security: Uses constant-time comparison to prevent timing attacks that could
// reveal information about the correct password.
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

// PasswordPolicy defines the requirements that passwords must meet to be considered valid.
// This helps enforce strong passwords and prevent common weak passwords.
//
// Fields:
//   - MinLength: Minimum password length (default: 12)
//   - RequireUpper: Require at least one uppercase letter
//   - RequireLower: Require at least one lowercase letter
//   - RequireNumber: Require at least one numeric digit
//   - RequireSymbol: Require at least one special character
type PasswordPolicy struct {
	MinLength     int  // Minimum password length
	RequireUpper  bool // Require uppercase letters
	RequireLower  bool // Require lowercase letters
	RequireNumber bool // Require numeric digits
	RequireSymbol bool // Require special characters
}

// DefaultPasswordPolicy returns a sensible default password policy that enforces
// strong passwords. The default requires:
//   - Minimum 12 characters
//   - At least one uppercase letter
//   - At least one lowercase letter
//   - At least one number
//   - At least one special character
//
// This policy helps prevent common weak passwords while remaining user-friendly.
func DefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:     12,
		RequireUpper:  true,
		RequireLower:  true,
		RequireNumber: true,
		RequireSymbol: true,
	}
}

// ValidatePassword checks if a password meets the specified policy requirements.
// It performs various checks including length, character requirements, and
// common password patterns.
//
// Parameters:
//   - password: The password to validate
//   - policy: The password policy to enforce. If nil, DefaultPasswordPolicy is used.
//
// Returns:
//   - nil if the password meets all requirements
//   - An error describing which requirement was not met
//
// The function checks for:
//   - Minimum length
//   - Required character types (uppercase, lowercase, numbers, symbols)
//   - Common weak passwords
//   - Sequential characters (e.g., "123456", "abc")
//   - Repeated characters (e.g., "aaaaaa")
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

// isCommonPassword checks if the password matches a known common or weak password.
// This function uses a curated list of common passwords and also checks for
// sequential and repeated character patterns.
//
// Note: This is a simplified implementation. For production use, consider
// integrating with a larger password dictionary or a service that provides
// real-time password breach checking.
//
// Returns true if the password is considered common or weak.
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

// isSequential checks if the password contains sequences of 3 or more consecutive characters.
// This helps identify weak passwords like "123456", "abcdef", "321", "cba", etc.
//
// The function checks both forward sequences (e.g., "123", "abc") and reverse
// sequences (e.g., "321", "cba") anywhere in the password.
//
// Returns true if a sequence of 3+ consecutive characters is found.
func isSequential(password string) bool {
	if len(password) < 3 {
		return false
	}

	// Check for sequential characters (forward or reverse) of length 3 or more
	for i := 0; i <= len(password)-3; i++ {
		// Check forward sequence
		isSeq := true
		for j := 1; j < 3; j++ {
			if password[i+j] != password[i+j-1]+1 {
				isSeq = false
			break
		}
	}
		if isSeq {
		return true
	}

		// Check reverse sequence
		isRevSeq := true
		for j := 1; j < 3; j++ {
			if password[i+j] != password[i+j-1]-1 {
				isRevSeq = false
			break
			}
		}
		if isRevSeq {
			return true
		}
	}

	return false
}

// isRepeated checks if the password consists entirely of the same repeated character.
// This helps identify weak passwords like "aaaaaa", "111111", etc.
//
// Returns true if all characters in the password are identical.
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

// GenerateRandomPassword generates a cryptographically secure random password
// that meets the specified policy requirements. The password is guaranteed to
// include at least one character from each required character type.
//
// Parameters:
//   - length: Desired password length. If less than policy.MinLength, it will be
//     adjusted to meet the minimum requirement.
//   - policy: The password policy to follow. If nil, DefaultPasswordPolicy is used.
//
// Returns:
//   - A randomly generated password that meets all policy requirements
//   - An error if password generation fails (should not happen in normal operation)
//
// Security: Uses crypto/rand for secure random number generation. The generated
// password is shuffled to ensure randomness even after including required characters.
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

// randomInt returns a cryptographically secure random integer in the range [min, max).
// This function uses crypto/rand for secure random number generation.
//
// Parameters:
//   - min: Minimum value (inclusive)
//   - max: Maximum value (exclusive)
//
// Returns:
//   - A random integer in the specified range
//   - If crypto/rand fails (extremely rare), falls back to time-based randomness
//
// Note: In the extremely unlikely event that crypto/rand fails, the function
// logs an error and uses a time-based fallback. This prevents panics but
// should be monitored in production.
func randomInt(min, max int) int {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		// Log error and return a fallback value instead of panicking
		// This prevents the application from crashing
		logrus.WithError(err).Error("Failed to generate random number, using fallback")
		// Use a simple fallback: current time nanoseconds modulo range
		if min == max {
			return min
		}
		if min > max {
			min, max = max, min
		}
		return min + (int(time.Now().UnixNano()) % (max - min))
	}

	r := int(buf[0])<<56 | int(buf[1])<<48 | int(buf[2])<<40 | int(buf[3])<<32 |
		int(buf[4])<<24 | int(buf[5])<<16 | int(buf[6])<<8 | int(buf[7])

	if min == max {
		return min
	}

	if min > max {
		min, max = max, min
	}

	// Ensure positive modulo result
	mod := r % (max - min)
	if mod < 0 {
		mod = -mod
	}

	return min + mod
}

// shuffleBytes shuffles a byte slice in place using the Fisher-Yates algorithm
// with cryptographically secure random number generation. This ensures the
// password characters are in a random order even after including required
// character types.
//
// Parameters:
//   - b: The byte slice to shuffle (modified in place)
func shuffleBytes(b []byte) {
	for i := range b {
		j := randomInt(i, len(b))
		b[i], b[j] = b[j], b[i]
	}
}
