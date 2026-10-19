package base62

import (
	"fmt"
	"math"
)

const (
	alphabet        = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	base            = uint32(len(alphabet))
	maxBase62Digits = 6 // max number of digits required to encode MaxUint32

)

var (
	ErrEmptyString = fmt.Errorf("empty string")
	ErrInvalidChar = fmt.Errorf("invalid character")
	ErrOverflow    = fmt.Errorf("integer overflow")
)

// Fixed-size arrays have better performance and lower memory overhead compared to maps for small static sets of data
var charToIndex [123]int8 // Assuming ASCII from '\0' - 'z'

func init() {
	for i := range charToIndex {
		charToIndex[i] = -1
	}
	for i, c := range alphabet {
		charToIndex[c] = int8(i)
	}
}

// Encode encodes a uint32 value to a base62 string.
// The returned string will be between 1-6 characters long.
func Encode(n uint32) string {
	if n < base {
		return string(alphabet[n])
	}
	// avoid dynamic memory usage for small, fixed size data
	buf := [maxBase62Digits]byte{}
	idx := len(buf)

	for n > 0 {
		idx--
		buf[idx] = alphabet[n%base]
		n /= base
	}

	return string(buf[idx:])
}

// Decode decodes a base62 string to a uint32 value.
// Returns an error if the input string is empty, contains invalid characters,
// or would result in integer overflow.
func Decode(encoded string) (uint32, error) {
	if len(encoded) == 0 {
		return 0, ErrEmptyString
	}
	var decoded uint32
	for _, char := range encoded {
		index := int8(-1)
		if int(char) < len(charToIndex) {
			index = charToIndex[char]
		}
		if index < 0 {
			return 0, fmt.Errorf("%w: %c", ErrInvalidChar, char)
		}
		// Add overflow check when calculating the decoded value to prevent silent overflow of uint32
		if decoded > (math.MaxUint32-uint32(index))/base {
			return 0, fmt.Errorf("%w: %s", ErrOverflow, encoded)
		}

		decoded = decoded*base + uint32(index)
	}

	return decoded, nil
}
