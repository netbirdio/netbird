package profilemanager

import "errors"

var (
	ErrProfileNotFound      = errors.New("profile not found")
	ErrProfileAlreadyExists = errors.New("profile already exists")
	ErrNoActiveProfile      = errors.New("no active profile set")

	// ErrAmbiguousActiveProfile is returned when the active profile state names
	// an ID that several profiles hold and does not say whose directory the
	// active one sits in.
	ErrAmbiguousActiveProfile = errors.New("active profile is ambiguous")
)
