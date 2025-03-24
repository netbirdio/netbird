package types

import "github.com/netbirdio/netbird/util"

// MgmtConfigPath Config path of the Management service
var MgmtConfigPath string

// Relay configuration type
type Relay struct {
	Addresses      []string
	CredentialsTTL util.Duration
	Secret         string
}
