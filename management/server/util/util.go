package util

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

