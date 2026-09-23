package certproof

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
)

func TestRunHelper_ProofSurvivesTheProcessBoundary(t *testing.T) {
	ca := certtest.NewCA(t, "corp-root")
	dir := t.TempDir()
	key := certtest.ECDSAKey(t)
	writeFile(t, dir, "device.pem", certtest.CertPEM(ca.Issue(t, key, "device"))+certtest.KeyPEM(t, key))

	challenger := certposture.NewChallenger([]byte("secret"))
	nonce := challenger.Nonce(peerKey, time.Now())
	request, err := json.Marshal(HelperRequest{
		PeerKey:    peerKey,
		Challenges: []HelperChallenge{{Nonce: nonce, CACertificates: []string{ca.PEM}}},
	})
	require.NoError(t, err, "request must encode")

	var stdout bytes.Buffer
	require.NoError(t, runHelper(context.Background(), NewFileStore(dir), bytes.NewReader(request), &stdout))

	var resp HelperResponse
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &resp), "helper must emit decodable JSON")
	require.Len(t, resp.Proofs, 1, "the matching certificate should produce one proof")

	// Verify exactly as management does, so the proof is proven to survive the encode,
	// the process boundary and the decode intact.
	chain, err := challenger.Verify(resp.Proofs[0], peerKey, time.Now())
	require.NoError(t, err, "the decoded proof must verify against the issued nonce")
	assert.Equal(t, "device", chain[0].Subject.CommonName, "the proven leaf should be the device certificate")
}

func TestRunHelper_NoChallengesYieldsEmptyResponse(t *testing.T) {
	request, err := json.Marshal(HelperRequest{PeerKey: peerKey})
	require.NoError(t, err)

	var stdout bytes.Buffer
	require.NoError(t, runHelper(context.Background(), NewFileStore(t.TempDir()), bytes.NewReader(request), &stdout))

	var resp HelperResponse
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &resp), "an empty request must still emit valid JSON")
	assert.Empty(t, resp.Proofs, "no challenges should produce no proofs")
}

func TestRunHelper_RejectsMalformedRequest(t *testing.T) {
	var stdout bytes.Buffer
	err := runHelper(context.Background(), NewFileStore(t.TempDir()), bytes.NewReader([]byte("not json")), &stdout)

	require.Error(t, err, "a malformed request must fail rather than emit an empty proof set")
	assert.Empty(t, stdout.String(), "nothing should be written to stdout on a decode failure")
}
