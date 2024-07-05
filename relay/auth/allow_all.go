package auth

// AllowAllAuth is a Validator that allows all connections.
type AllowAllAuth struct {
}

func (a *AllowAllAuth) Validate(any) error {
	return nil
}
