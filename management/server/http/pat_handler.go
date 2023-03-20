package http

import (
	"github.com/netbirdio/netbird/management/server"
	"github.com/netbirdio/netbird/management/server/jwtclaims"
)

// PATHandler is the nameserver group handler of the account
type PATHandler struct {
	accountManager  server.AccountManager
	claimsExtractor *jwtclaims.ClaimsExtractor
}

func NewPATsHandler(accountManager server.AccountManager, authCfg AuthCfg) {

}
