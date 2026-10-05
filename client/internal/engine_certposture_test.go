//go:build !windows && !darwin

package internal

import (
	"context"
	"os"
	"path/filepath"
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
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestCertPostureState_Record(t *testing.T) {
	now := time.Now()

	var proven certPostureState
	assert.False(t, proven.record("", true, now), "a first collection that proves something is not news")

	var unproven certPostureState
	assert.True(t, unproven.record("", false, now), "a first collection that proves nothing is reported")
	assert.False(t, unproven.record("", false, now), "the same outcome again is not reported twice")
	assert.True(t, unproven.record("", true, now), "proving again is reported")
	assert.True(t, unproven.record("", false, now), "losing the proof again is reported")
}

func TestCertPostureState_Stale(t *testing.T) {
	now := time.Now()
	var s certPostureState

	assert.False(t, s.stale("", now), "before any collection the sync itself collects")

	s.record("501:alice", true, now)
	assert.False(t, s.stale("501:alice", now.Add(time.Hour)), "a proven collection for the same user stays fresh")
	assert.True(t, s.stale("", now), "the user logging out changes what can be proven")
	assert.True(t, s.stale("502:bob", now), "another owner session changes what can be proven")

	s.record("", false, now)
	assert.False(t, s.stale("", now.Add(certRetryInterval-time.Second)), "an unproven collection is not retried before the interval")
	assert.True(t, s.stale("", now.Add(certRetryInterval)), "an unproven collection is retried once the interval passed")
}

// attachCertificateProofs against a real PEM directory and status recorder: a device that
// cannot prove its certificate gets one warning, and one notice when it can again.
func TestEngine_AttachCertificateProofsReportsLostAndRegainedProofs(t *testing.T) {
	// The store refuses a group-writable directory, which t.TempDir yields under a
	// user-private-group umask.
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	recorder := peer.NewRecorder("")
	e := &Engine{
		ctx:            context.Background(),
		config:         &EngineConfig{WgPrivateKey: key, CertStore: certproof.Config{Dir: dir}},
		statusRecorder: recorder,
	}

	ca := certtest.NewCA(t, "corp-root")
	peerKey := key.PublicKey()
	nonce := certposture.NewChallenger([]byte("secret")).Nonce(peerKey[:], time.Now())
	checks := []*mgmProto.Checks{{CertificateChallenge: &mgmProto.CertificateChallenge{Nonce: nonce, CaCertificates: []string{ca.PEM}}}}

	warnings := func() int {
		n := 0
		for _, ev := range recorder.GetEventHistory() {
			if ev.Severity == cProto.SystemEvent_WARNING && ev.Category == cProto.SystemEvent_SYSTEM {
				n++
			}
		}
		return n
	}

	info := &system.Info{}
	e.attachCertificateProofs(info, checks)
	assert.Empty(t, info.CertificateProofs, "no certificate in the store yet")
	assert.Equal(t, 1, warnings(), "the user is told the device proves no certificate")

	e.attachCertificateProofs(info, checks)
	assert.Equal(t, 1, warnings(), "an unchanged outcome is not reported again")

	deviceKey := certtest.ECDSAKey(t)
	pem := certtest.CertPEM(ca.Issue(t, deviceKey, "device")) + certtest.KeyPEM(t, deviceKey)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "device.pem"), []byte(pem), 0o600))

	e.attachCertificateProofs(info, checks)
	assert.Len(t, info.CertificateProofs, 1, "the certificate is proven once it is in the store")
	events := recorder.GetEventHistory()
	require.NotEmpty(t, events)
	last := events[len(events)-1]
	assert.Equal(t, cProto.SystemEvent_INFO, last.Severity, "regaining the proof is reported as good news")

	e.attachCertificateProofs(&system.Info{}, []*mgmProto.Checks{{Files: []string{"/bin/agent"}}})
	assert.Len(t, recorder.GetEventHistory(), len(events), "checks without a certificate challenge collect and report nothing")
}

func TestCertPostureState_UndeliveredIsStale(t *testing.T) {
	now := time.Now()
	var s certPostureState

	s.record("501:alice", true, now)
	require.False(t, s.stale("501:alice", now), "precondition: a delivered proof for the same user is fresh")

	s.undelivered()
	assert.True(t, s.stale("501:alice", now), "a proof management never received is collected and sent again")

	s.record("501:alice", true, now)
	assert.False(t, s.stale("501:alice", now), "a later successful collection is fresh again")
}
