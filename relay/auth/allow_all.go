package auth

// AllowAllAuth is a Validator that allows all connections.
// Used this for testing purposes only.
type AllowAllAuth struct {
}

func (a *AllowAllAuth) Validate(any) error {
	return nil
}
