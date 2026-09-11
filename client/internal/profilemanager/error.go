package profilemanager

import "errors"

var (
	ErrProfileNotFound      = errors.New("profile not found")
	ErrProfileAlreadyExists = errors.New("profile already exists")
	ErrNoActiveProfile      = errors.New("no active profile set")
)
