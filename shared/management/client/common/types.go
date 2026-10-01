package common

// LoginFlag introduces additional login flags to the PKCE authorization request.
//
// # Config Values
//
//	| Value | Flag                 | OAuth Parameters                        |
//	|-------|----------------------|-----------------------------------------|
//	| 0     | LoginFlagPromptLogin | prompt=login                            |
//	| 1     | LoginFlagMaxAge0     | max_age=0                               |
type LoginFlag uint8

const (
	// LoginFlagPromptLogin adds prompt=login to the authorization request
	LoginFlagPromptLogin LoginFlag = iota
	// LoginFlagMaxAge0 adds max_age=0 to the authorization request
	LoginFlagMaxAge0
	// LoginFlagNone disables all login flags
	LoginFlagNone
)
