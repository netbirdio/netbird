package allow

// Auth is a Validator that allows all connections.
// Used this for testing purposes only.
type Auth struct {
}

func (a *Auth) Validate(any) error {
	return nil
}

func (a *Auth) ValidateHelloMsgType(any) error {
	return nil
}
