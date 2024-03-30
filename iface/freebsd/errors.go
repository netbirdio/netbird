package freebsd

import "errors"

// ErrDoesNotExist represents a custom error indicating that interface does not exist.
var (
	ErrDoesNotExist     = errors.New("does not exist")
	ErrNameDoesNotMatch = errors.New("name does not match")
)
