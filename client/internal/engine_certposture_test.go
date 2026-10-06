//go:build !windows && !darwin

package internal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/certproof"
	"github.com/netbirdio/netbird/client/internal/peer"
	cProto "github.com/netbirdio/netbird/client/proto"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/shared/management/certposture"
	"github.com/netbirdio/netbird/shared/management/certposture/certtest"
	mgmt "github.com/netbirdio/netbird/shared/management/client"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestCertPostureState_Record(t *testing.T) {
	now := time.Now()
	one := []certposture.Proof{{}}

	var proven certPostureState
	assert.False(t, proven.record("k", "", one, now), "a first collection that proves something is not news")

	var unproven certPostureState
	assert.True(t, unproven.record("k", "", nil, now), "a first collection that proves nothing is reported")
	assert.False(t, unproven.record("k", "", nil, now), "the same outcome again is not reported twice")
	assert.True(t, unproven.record("k", "", one, now), "proving again is reported")
	assert.True(t, unproven.record("k", "", nil, now), "losing the proof again is reported")
}

func TestCertPostureState_NeedsCollection(t *testing.T) {
	now := time.Now()
	one := []certposture.Proof{{}}
	var s certPostureState

	assert.True(t, s.needsCollection("k", "", now), "nothing collected yet")

	s.record("k", "501:alice", one, now)
	assert.False(t, s.needsCollection("k", "501:alice", now.Add(time.Hour)), "a proven collection for the same challenges and user stays fresh")
	assert.True(t, s.needsCollection("other", "501:alice", now), "new challenges, such as a rotated nonce, are answered again")
	assert.True(t, s.needsCollection("k", "", now), "the user logging out changes what can be proven")
	assert.True(t, s.needsCollection("k", "502:bob", now), "another owner session changes what can be proven")

	s.record("k", "", nil, now)
	assert.False(t, s.needsCollection("k", "", now.Add(certRetryInterval-time.Second)), "an unproven collection is not retried before the interval")
	assert.True(t, s.needsCollection("k", "", now.Add(certRetryInterval)), "an unproven collection is retried once the interval passed")

	s.record("k", "501:alice", one, now)
	s.undelivered()
	assert.True(t, s.needsCollection("k", "501:alice", now), "a proof management never received is collected and sent again")
}

// TestCertPostureState_CachedProofsAcrossNonceRotation: management rotates the nonce every
// window and accepts the previous one, so a cached proof keeps being attached across one
// rotation, while the watcher signs the new nonce, and not across two.
func TestCertPostureState_CachedProofsAcrossNonceRotation(t *testing.T) {
	challenger := certposture.NewChallenger([]byte("secret"))
	peerKey := []byte("peer-public-key-aaaaaaaaaaaaaaaa")
	now := time.Now()
	checksAt := func(at time.Time) []*mgmProto.Checks {
		return []*mgmProto.Checks{{CertificateChallenge: &mgmProto.CertificateChallenge{Nonce: challenger.Nonce(peerKey, at)}}}
	}

	var s certPostureState
	current := checksAt(now)
	s.record(challengesKey(current), "", []certposture.Proof{{Nonce: current[0].CertificateChallenge.Nonce}}, now)

	assert.Len(t, s.cachedProofs(current), 1, "the proof for the current nonce is attached")
	assert.Len(t, s.cachedProofs(checksAt(now.Add(certposture.Window))), 1, "after one rotation the proof is still accepted and attached")
	assert.Empty(t, s.cachedProofs(checksAt(now.Add(2*certposture.Window))), "after two rotations management would reject it")
	assert.Empty(t, s.cachedProofs([]*mgmProto.Checks{{Files: []string{"/bin/agent"}}}), "no challenge, no proof")
}

// newCertPostureEngine is an engine whose certificate store is a real PEM directory and
// whose management client records the proofs of every meta sync.
func newCertPostureEngine(t *testing.T, recorder *peer.Status, syncMeta func(*system.Info) error) (*Engine, string, *certtest.CA) {
	t.Helper()
	// The store refuses a group-writable directory, which t.TempDir yields under a
	// user-private-group umask.
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	e := &Engine{
		ctx:            context.Background(),
		syncMsgMux:     &sync.Mutex{},
		config:         &EngineConfig{WgPrivateKey: key, CertStore: certproof.Config{Dir: dir}},
		statusRecorder: recorder,
		mgmClient:      &mgmt.MockClient{SyncMetaFunc: syncMeta},
	}
	ca := certtest.NewCA(t, "corp-root")
	peerKey := key.PublicKey()
	nonce := certposture.NewChallenger([]byte("secret")).Nonce(peerKey[:], time.Now())
	e.checks = []*mgmProto.Checks{{CertificateChallenge: &mgmProto.CertificateChallenge{Nonce: nonce, CaCertificates: []string{ca.PEM}}}}
	return e, dir, ca
}

func writeDeviceCert(t *testing.T, dir string, ca *certtest.CA) string {
	t.Helper()
	deviceKey := certtest.ECDSAKey(t)
	pem := certtest.CertPEM(ca.Issue(t, deviceKey, "device")) + certtest.KeyPEM(t, deviceKey)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "device.pem"), []byte(pem), 0o600))
	return pem
}

// TestEngine_AttachCertificateProofsNeverCollects: the sync path only attaches what the
// watcher collected, so a certificate that appears in the store is not proven on the sync
// path until the watcher ran.
func TestEngine_AttachCertificateProofsNeverCollects(t *testing.T) {
	e, dir, ca := newCertPostureEngine(t, nil, func(*system.Info) error { return nil })
	writeDeviceCert(t, dir, ca)

	info := &system.Info{}
	e.attachCertificateProofs(info, e.checks)
	assert.Empty(t, info.CertificateProofs, "the sync path does not collect")

	require.NoError(t, e.refreshCertificateProofs())
	e.attachCertificateProofs(info, e.checks)
	assert.Len(t, info.CertificateProofs, 1, "the sync path attaches what the watcher collected")
}

// TestEngine_RefreshReportsLostAndRegainedProofs: a device that cannot prove its
// certificate gets one warning, and one notice when it can again.
func TestEngine_RefreshReportsLostAndRegainedProofs(t *testing.T) {
	recorder := peer.NewRecorder("")
	e, dir, ca := newCertPostureEngine(t, recorder, func(*system.Info) error { return nil })
	warnings := func() int {
		n := 0
		for _, ev := range recorder.GetEventHistory() {
			if ev.Severity == cProto.SystemEvent_WARNING && ev.Category == cProto.SystemEvent_SYSTEM {
				n++
			}
		}
		return n
	}
	expire := func() { e.certState.attemptedAt = time.Now().Add(-certRetryInterval) }

	require.NoError(t, e.refreshCertificateProofs())
	assert.Equal(t, 1, warnings(), "the user is told the device proves no certificate")

	expire()
	require.NoError(t, e.refreshCertificateProofs())
	assert.Equal(t, 1, warnings(), "an unchanged outcome is not reported again")

	writeDeviceCert(t, dir, ca)
	expire()
	require.NoError(t, e.refreshCertificateProofs())
	events := recorder.GetEventHistory()
	require.NotEmpty(t, events)
	assert.Equal(t, cProto.SystemEvent_INFO, events[len(events)-1].Severity, "regaining the proof is reported as good news")
}

// TestEngine_RefreshSendsOnlyChangedProofs: every meta sync makes management recompute
// and push network maps, so a collection that proves the same chains as before must not
// send, while a new certificate or a failed delivery must.
func TestEngine_RefreshSendsOnlyChangedProofs(t *testing.T) {
	var sent [][]certposture.Proof
	failSync := false
	e, dir, ca := newCertPostureEngine(t, nil, func(info *system.Info) error {
		if failSync {
			return errors.New("management unavailable")
		}
		sent = append(sent, info.CertificateProofs)
		return nil
	})
	// expire makes the last collection due for the unproven retry.
	expire := func() { e.certState.attemptedAt = time.Now().Add(-certRetryInterval) }
	// switchUser makes the last collection stale as if another user signed in.
	switchUser := func() { e.certState.userContext = "someone else" }

	require.NoError(t, e.refreshCertificateProofs())
	require.Len(t, sent, 1, "the first collection is sent")
	assert.Empty(t, sent[0], "nothing to prove yet")

	expire()
	require.NoError(t, e.refreshCertificateProofs())
	assert.Len(t, sent, 1, "still proving nothing is not sent again")

	pem := writeDeviceCert(t, dir, ca)
	expire()
	require.NoError(t, e.refreshCertificateProofs())
	require.Len(t, sent, 2, "a newly proven certificate is sent")
	assert.Len(t, sent[1], 1, "the new proof is attached")

	switchUser()
	require.NoError(t, e.refreshCertificateProofs())
	assert.Len(t, sent, 2, "the same chain proven again, with a fresh signature, is not sent")

	failSync = true
	require.NoError(t, os.Remove(filepath.Join(dir, "device.pem")))
	switchUser()
	require.Error(t, e.refreshCertificateProofs())
	failSync = false
	require.NoError(t, os.WriteFile(filepath.Join(dir, "device.pem"), []byte(pem), 0o600))

	// Management missed the empty proof set, so it still holds the chain the device proves
	// again now; after a failed delivery the state is unknown, and it is sent regardless.
	require.NoError(t, e.refreshCertificateProofs())
	assert.Len(t, sent, 3, "after a failed delivery the next collection is sent")
}
