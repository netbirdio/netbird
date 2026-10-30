package grpc

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"

	log "github.com/sirupsen/logrus"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
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

func peerAuthKeys(peer *nbpeer.Peer) PeerAuthKeys {
	return PeerAuthKeys{WGPubKey: peer.Key, AuthPubKey: peer.AuthPubKey}
}

// relayCredentials returns the peer's auth token, or the legacy relay token when the peer gets
// no auth token. Never both: the client takes the auth token whenever it is present.
func (s *Server) relayCredentials(ctx context.Context, peer *nbpeer.Peer) (*Token, []byte) {
	authToken, err := s.secretsManager.GenerateAuthToken(peerAuthKeys(peer))
	if err != nil {
		log.WithContext(ctx).Errorf("failed generating auth token for peer %s: %v", peer.ID, err)
	}
	if authToken != nil || s.config.Relay == nil || len(s.config.Relay.Addresses) == 0 {
		return nil, authToken
	}
	relayToken, err := s.secretsManager.GenerateRelayToken()
	if err != nil {
		log.WithContext(ctx).Errorf("failed generating Relay token: %v", err)
	}
	return relayToken, nil
}
