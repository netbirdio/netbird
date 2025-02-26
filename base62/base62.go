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
	var decoded uint32
	strLen := len(encoded)

	for i, char := range encoded {
		index := strings.IndexRune(alphabet, char)
		if index < 0 {
			return 0, fmt.Errorf("invalid character: %c", char)
		}

		decoded += uint32(index) * uint32(math.Pow(float64(base), float64(strLen-i-1)))
	}

	return decoded, nil
}

// Reverse a string.
func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
