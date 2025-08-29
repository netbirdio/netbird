package templates

import (
	_ "embed"
)

//go:embed pkce-auth-msg.html
var PKCEAuthMsgTmpl string
