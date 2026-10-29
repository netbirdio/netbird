package util

import (
	"crypto/rand"
	"math/big"
)

// RandIntn returns a uniformly distributed int in [0, n) sourced from
// crypto/rand. It panics if n <= 0 or the platform randomness source fails.
func RandIntn(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(err)
	}
	return int(v.Int64())
}

// Difference returns the elements in `a` that aren't in `b`.
func Difference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

// ToPtr returns a pointer to the given value.
func ToPtr[T any](value T) *T {
	return &value
}
