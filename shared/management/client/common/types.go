package common

// LoginFlag introduces additional login flags to the PKCE authorization request.
//
// # Config Values
//
//	| Value | Flag                 | OAuth Parameters                        |
//	|-------|----------------------|-----------------------------------------|
//	| 0     | LoginFlagPromptLogin | prompt=select_account login             |
//	| 1     | LoginFlagMaxAge0     | max_age=0 & prompt=select_account       |
type LoginFlag uint8

const (
	// LoginFlagPromptLogin adds prompt=select_account login to the authorization request
	LoginFlagPromptLogin LoginFlag = iota
	// LoginFlagMaxAge0 adds max_age=0 and prompt=select_account to the authorization request
	LoginFlagMaxAge0
	// LoginFlagNone disables all login flags
	LoginFlagNone
)
