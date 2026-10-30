package grpc

import (
	"crypto/ed25519"
	"encoding/base64"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/management/proto"
)

// loginAuthPubKey returns the peer's auth key from the login request, base64 encoded. A missing or
// malformed key yields empty: the peer then gets legacy Signal and Relay tokens.
func loginAuthPubKey(req *proto.LoginRequest) string {
	key := req.GetPeerKeys().GetAuthPubKey()
	if len(key) == 0 {
		return ""
	}
	if len(key) != ed25519.PublicKeySize {
		log.Infof("ignoring malformed peer auth key of %d bytes, the peer gets legacy tokens", len(key))
		return ""
	}
	return base64.StdEncoding.EncodeToString(key)
}
