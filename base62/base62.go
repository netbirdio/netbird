package base62

import (
	"fmt"
	"math"
	"strings"
)

const (
	alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	base     = uint32(len(alphabet))
)

// Encode encodes a uint32 value to a base62 string.
func Encode(n uint32) string {
	if n < base {
		return string(alphabet[n])
	}
	// avoid dynamic memory usage for small, fixed size data
	buf := [6]byte{} // 6 is max number of digits required to encode MaxUint32
	idx := len(buf)

	for n > 0 {
		idx--
		buf[idx] = alphabet[n%base]
		n /= base
	}

	return string(buf[idx:])
}

// Decode decodes a base62 string to a uint32 value.
func Decode(encoded string) (uint32, error) {
	if len(encoded) == 0 {
		return 0, fmt.Errorf("empty string")
	}
	var decoded uint32
	for _, char := range encoded {
		index := strings.IndexRune(alphabet, char)
		if index < 0 {
			return 0, fmt.Errorf("invalid character: %c", char)
		}
		// Add overflow check when calculating the decoded value to prevent silent overflow of uint32
		if decoded > (math.MaxUint32-uint32(index))/base {
			return 0, fmt.Errorf("integer overflow")
		}

		decoded = decoded*base + uint32(index)
	}

	return decoded, nil
}
