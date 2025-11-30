package common

// LoginFlag introduces additional login flags to the PKCE authorization request.
//
// # Config Values
//
//	| Value | Flag                          | OAuth Parameters                  |
//	|-------|-------------------------------|-----------------------------------|
//	| 0     | LoginFlagPromptLogin          | prompt=login                      |
//	| 1     | LoginFlagMaxAge0              | max_age=0                         |
//	| 2     | LoginFlagSelectAccount        | prompt=select_account             |
//	| 3     | LoginFlagSelectAccountMaxAge0 | prompt=select_account & max_age=0 |
//	| 4     | LoginFlagNone                 | (none)                            |
//
// # Behavior
//
//	| Scenario                   | None          | PromptLogin       | MaxAge0           | SelectAccount     | SelectAccountMaxAge0            |
//	|----------------------------|---------------|-------------------|-------------------|-------------------|---------------------------------|
//	| 1 account, active session  | Auto login    | Password required | Password required | Auto login*       | Account selector + pwd required |
//	| 2 accounts, both active    | Auto login    | Password required | Password required | Account selector  | Account selector + pwd required |
//	| No session                 | Login form    | Login form        | Login form        | Login form        | Login form                      |
//
// * Some IDPs show account selector even with single account, others auto-login.
//
// # Use Cases
//
//	| Use Case                       | Recommended Flag          |
//	|--------------------------------|---------------------------|
//	| Default SSO behavior           | LoginFlagNone (4)         |
//	| Multi-account environment      | LoginFlagSelectAccount (2)|
//	| Security-sensitive operations  | LoginFlagPromptLogin (0)  |
//	| Multi-account + force reauth   | LoginFlagSelectAccountMaxAge0 (3) |
type LoginFlag uint8

const (
	// LoginFlagPromptLogin adds prompt=login to the authorization request
	LoginFlagPromptLogin LoginFlag = iota
	// LoginFlagMaxAge0 adds max_age=0 to the authorization request
	LoginFlagMaxAge0
	// LoginFlagSelectAccount adds prompt=select_account to the authorization request
	LoginFlagSelectAccount
	// LoginFlagSelectAccountMaxAge0 adds prompt=select_account and max_age=0
	LoginFlagSelectAccountMaxAge0
	// LoginFlagNone disables all login flags
	LoginFlagNone
)

// HasPromptLogin returns true if prompt=login should be added
func (f LoginFlag) HasPromptLogin() bool {
	return f == LoginFlagPromptLogin
}

// HasMaxAge0 returns true if max_age=0 should be added
func (f LoginFlag) HasMaxAge0() bool {
	return f == LoginFlagMaxAge0 || f == LoginFlagSelectAccountMaxAge0
}

// HasSelectAccount returns true if prompt=select_account should be added
func (f LoginFlag) HasSelectAccount() bool {
	return f == LoginFlagSelectAccount || f == LoginFlagSelectAccountMaxAge0
}
