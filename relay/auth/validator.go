package auth

import "hash"

// Validator is an interface that defines the Validate method.
type Validator interface {
	Validate(func() hash.Hash, any) error
}
