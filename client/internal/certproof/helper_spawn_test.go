//go:build (darwin && !ios) || windows

package certproof

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestHelperRequest_CarriesEveryChallenge(t *testing.T) {
	ca := certtest.NewCA(t, "corp-root")
	challenges := []*proto.CertificateChallenge{
		{Nonce: []byte("first"), CaCertificates: []string{ca.PEM}},
		{Nonce: []byte("second")},
	}

	req := helperRequest(challenges, peerKey)

	require.Len(t, req.Challenges, 2, "every challenge must reach the helper")
	assert.Equal(t, peerKey, req.PeerKey, "the peer key binds the signature to this machine")
	assert.Equal(t, []byte("first"), req.Challenges[0].Nonce, "the nonce must survive unchanged")
	assert.Equal(t, []string{ca.PEM}, req.Challenges[0].CACertificates, "the accepted CAs must survive unchanged")
	assert.Empty(t, req.Challenges[1].CACertificates, "a challenge without CAs stays without CAs")
}
