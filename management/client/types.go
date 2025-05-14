package client

// LoginFlag introduces additional login flags to the PKCE authorization request
type LoginFlag uint8

const (
	// LoginFlagDisabled disables additional login flags
	LoginFlagDisabled LoginFlag = iota
	// LoginFlagPrompt adds prompt=login to the authorization request
	LoginFlagPrompt
	// LoginFlagMaxAge0 adds max_age=0 to the authorization request
	LoginFlagMaxAge0
)

func (l LoginFlag) IsPromptLogin() bool {
	return l == LoginFlagPrompt
}

func (l LoginFlag) IsMaxAge0Login() bool {
	return l == LoginFlagMaxAge0
}
