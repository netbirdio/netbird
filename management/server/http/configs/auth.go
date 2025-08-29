package configs

// AuthCfg contains parameters for authentication middleware
type AuthCfg struct {
	Issuer       string
	Audience     string
	UserIDClaim  string
	KeysLocation string
}
