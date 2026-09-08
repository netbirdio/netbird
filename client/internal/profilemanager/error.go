package profilemanager

import "errors"

var (
	ErrProfileNotFound      = errors.New("profile not found")
	ErrProfileAlreadyExists = errors.New("profile already exists")
	ErrNoActiveProfile      = errors.New("no active profile set")

	// ErrConfigWithoutIdentity is returned for a serialized config that carries
	// no WireGuard or SSH key. See ConfigFromJSON for why it is refused rather
	// than provisioned.
	ErrConfigWithoutIdentity = errors.New("config carries no peer identity: log in to provision one before loading a stored config")
)
