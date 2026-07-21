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

type comparableObject[T any] interface {
	Equal(other T) bool
}

func MergeUnique[T comparableObject[T]](arr1, arr2 []T) []T {
	var result []T

	for _, item := range arr1 {
		if !contains(result, item) {
			result = append(result, item)
		}
	}

	for _, item := range arr2 {
		if !contains(result, item) {
			result = append(result, item)
		}
	}

	return result
}

func contains[T comparableObject[T]](slice []T, element T) bool {
	for _, item := range slice {
		if item.Equal(element) {
			return true
		}
	}
	return false
}
