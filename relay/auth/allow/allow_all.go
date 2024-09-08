package allow

import "hash"

// Auth is a Validator that allows all connections.
// Used this for testing purposes only.
type Auth struct {
}

func (a *Auth) Validate(func() hash.Hash, any) error {
	return nil
}
