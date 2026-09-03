//go:build e2e

package remotejobs

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

const (
	refusedReason = "remote jobs are not enabled on this peer"
	// testUploadURL is the debug-bundle upload URL the job subtests pass; it only
	// needs to be a well-formed https URL with a host (see ValidateBundleUploadURL).
	testUploadURL = "https://uploads.example.com/bundle"
)

// TestRemoteJobsOptInAndBundleParams exercises the two PRs end-to-end against a
// live management server and a real client:
//
//   - #7153: the peer's remote-jobs opt-in defaults off, is reported to
//     management (visible via the peers API as remote_jobs_allowed), and gates
//     job execution on the client — a streamed job is refused until the peer
//     opts in with `netbird up --allow-remote-jobs`, after which it runs.
//   - #7147: the debug-bundle job's anonymize_level is validated (an unknown
//     value is rejected at creation) and normalized (trimmed + lowercased) in
//     the stored job the API returns.
func TestRemoteJobsOptInAndBundleParams(t *testing.T) {
	ctx := context.Background()

	// A group for the setup key to auto-assign; peers must land in some group.
	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-remotejobs"})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-remotejobs",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")
	t.Cleanup(func() { _ = srv.API().SetupKeys.Delete(context.Background(), sk.Id) })

	// Start the client with a plain `netbird up` (remote jobs NOT enabled).
	cl, err := harness.StartClient(ctx, srv, sk.Key)
	require.NoError(t, err, "start client")
	t.Cleanup(func() { _ = cl.Terminate(context.Background()) })
	require.NoError(t, cl.WaitConnected(ctx, 90*time.Second), "client must connect to management")

	peerID := waitForPeer(ctx, t, cl.Hostname())

	t.Run("opt-in flag defaults to false and is reported to management (#7153)", func(t *testing.T) {
		p, err := srv.API().Peers.Get(ctx, peerID)
		require.NoError(t, err)
		allowed := remoteJobsAllowed(p)
		require.NotNil(t, allowed, "remote_jobs_allowed must be present on the peer API")
		assert.False(t, *allowed, "a peer that ran plain `netbird up` must default to opt-out")
	})

	t.Run("anonymize_level is validated and normalized (#7147)", func(t *testing.T) {
		// Unknown level is rejected at job creation.
		_, err := srv.API().Peers.Jobs(peerID).Create(ctx, bundleJob("bogus", testUploadURL))
		require.Error(t, err, "an unknown anonymize_level must be rejected")
		assert.Contains(t, strings.ToLower(err.Error()), "anonymize_level",
			"the rejection must name the offending field")

		// A messy but valid level is normalized (trimmed + lowercased) in the
		// stored job the API echoes back.
		job, err := srv.API().Peers.Jobs(peerID).Create(ctx, bundleJob("  Strict  ", testUploadURL))
		require.NoError(t, err, "a valid anonymize_level must be accepted")
		bw, err := job.Workload.AsBundleWorkloadResponse()
		require.NoError(t, err, "job workload must be a bundle")
		require.NotNil(t, bw.Parameters.AnonymizeLevel)
		assert.Equal(t, "strict", *bw.Parameters.AnonymizeLevel,
			"anonymize_level must be normalized to trimmed lowercase")
		waitForJobTerminal(ctx, t, peerID, job.Id) // let it settle before the next create
	})

	t.Run("a job is refused while the peer has not opted in (#7153 enforcement)", func(t *testing.T) {
		job, err := srv.API().Peers.Jobs(peerID).Create(ctx, bundleJob("default", testUploadURL))
		require.NoError(t, err, "job creation itself is allowed; enforcement is on the client")
		final := waitForJobTerminal(ctx, t, peerID, job.Id)
		assert.Equal(t, api.JobResponseStatusFailed, final.Status, "the client must refuse the job")
		require.NotNil(t, final.FailedReason)
		assert.Contains(t, *final.FailedReason, refusedReason,
			"the failure must be the opt-out refusal, not some other error")
	})

	t.Run("opting in flips the flag and lets the job run (#7153)", func(t *testing.T) {
		require.NoError(t, cl.Up(ctx, "--allow-remote-jobs"), "re-run up with --allow-remote-jobs")
		require.NoError(t, cl.WaitConnected(ctx, 90*time.Second), "client must reconnect")

		// The new opt-in must round-trip to management and surface on the API.
		require.Eventually(t, func() bool {
			p, err := srv.API().Peers.Get(ctx, peerID)
			if err != nil {
				return false
			}
			allowed := remoteJobsAllowed(p)
			return allowed != nil && *allowed
		}, 60*time.Second, 2*time.Second, "remote_jobs_allowed must become true after opt-in")

		// The same job that was refused before must now be accepted for
		// execution: whatever its outcome, it must NOT be the opt-out refusal.
		job, err := srv.API().Peers.Jobs(peerID).Create(ctx, bundleJob("default", testUploadURL))
		require.NoError(t, err)
		final := waitForJobTerminal(ctx, t, peerID, job.Id)
		if final.Status == api.JobResponseStatusFailed && final.FailedReason != nil {
			assert.NotContains(t, *final.FailedReason, refusedReason,
				"once opted in, the job must not be refused for opt-out; any failure must be for another reason (e.g. upload)")
		}
	})
}

// remoteJobsAllowed returns the peer's remote-jobs opt-in flag from the API
// response (nil if the peer or its local flags are absent).
func remoteJobsAllowed(p *api.Peer) *bool {
	if p == nil || p.LocalFlags == nil {
		return nil
	}
	return p.LocalFlags.RemoteJobsAllowed
}

// bundleJob builds a debug-bundle job request with the given anonymize_level
// (omitted when empty) and upload_url (omitted when empty).
func bundleJob(anonymizeLevel, uploadURL string) api.JobRequest {
	params := api.BundleParameters{
		Anonymize:    true,
		LogFileCount: 1,
	}
	if anonymizeLevel != "" {
		params.AnonymizeLevel = &anonymizeLevel
	}
	if uploadURL != "" {
		params.UploadUrl = &uploadURL
	}
	var wl api.WorkloadRequest
	// FromBundleWorkloadRequest cannot fail for a well-formed value.
	_ = wl.FromBundleWorkloadRequest(api.BundleWorkloadRequest{
		Type:       api.WorkloadTypeBundle,
		Parameters: params,
	})
	return api.JobRequest{Workload: wl}
}

// waitForPeer polls the peers API until the client that registered under the
// given hostname appears and returns its ID. Matching by hostname rather than
// taking the first list entry keeps the test correct if the account ever holds
// more than one peer (a shared bootstrap account, or a second client added to
// the package).
func waitForPeer(ctx context.Context, t *testing.T, hostname string) string {
	t.Helper()
	var peerID string
	require.Eventually(t, func() bool {
		peers, err := srv.API().Peers.List(ctx)
		if err != nil {
			return false
		}
		for _, p := range peers {
			if p.Hostname == hostname {
				peerID = p.Id
				return true
			}
		}
		return false
	}, 60*time.Second, 2*time.Second, "the client peer must register with management")
	return peerID
}

// waitForJobTerminal polls a job until it leaves the pending state, then returns
// the final response.
func waitForJobTerminal(ctx context.Context, t *testing.T, peerID, jobID string) *api.JobResponse {
	t.Helper()
	var final *api.JobResponse
	require.Eventually(t, func() bool {
		j, err := srv.API().Peers.Jobs(peerID).Get(ctx, jobID)
		if err != nil || j == nil {
			return false
		}
		if j.Status == api.JobResponseStatusPending {
			return false
		}
		final = j
		return true
	}, 120*time.Second, 2*time.Second, "job must reach a terminal state")
	return final
}
