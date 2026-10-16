//go:build (darwin && !ios) || windows

package certproof

import (
	"github.com/netbirdio/netbird/shared/management/proto"
)

func helperRequest(challenges []*proto.CertificateChallenge, peerKey []byte) HelperRequest {
	req := HelperRequest{PeerKey: peerKey, Challenges: make([]HelperChallenge, 0, len(challenges))}
	for _, challenge := range challenges {
		req.Challenges = append(req.Challenges, HelperChallenge{
			Nonce:          challenge.GetNonce(),
			CACertificates: challenge.GetCaCertificates(),
		})
	}
	return req
}
