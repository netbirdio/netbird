package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

func strPtr(s string) *string { return &s }

// bundleJobFromParams builds a bundle Job whose stored workload parameters are
// the marshalled REST BundleParameters, mirroring what NewJob persists.
func bundleJobFromParams(t *testing.T, p api.BundleParameters) *Job {
	t.Helper()
	raw, err := json.Marshal(p)
	require.NoError(t, err, "marshal bundle parameters")
	return &Job{
		ID: "job-1",
		Workload: Workload{
			Type:       JobTypeBundle,
			Parameters: raw,
			Result:     []byte("{}"),
		},
	}
}

// TestBuildStreamBundleResponse_CarriesIdentityAndUploadFields verifies the
// anonymize_level and upload_url REST fields are mapped onto the proto request
// the client receives.
func TestBuildStreamBundleResponse_CarriesIdentityAndUploadFields(t *testing.T) {
	job := bundleJobFromParams(t, api.BundleParameters{
		BundleFor:      true,
		BundleForTime:  2,
		LogFileCount:   100,
		Anonymize:      true,
		AnonymizeLevel: strPtr("strict"),
		UploadUrl:      strPtr("https://upload.example.com"),
	})

	req, err := job.ToStreamJobRequest()
	require.NoError(t, err, "ToStreamJobRequest must succeed")

	bundle := req.GetBundle()
	require.NotNil(t, bundle, "the request must carry bundle parameters")
	assert.Equal(t, "strict", bundle.GetAnonymizeLevel(), "anonymize_level must reach the client")
	assert.Equal(t, "https://upload.example.com", bundle.GetUploadUrl(), "upload_url must reach the client")
	assert.True(t, bundle.GetAnonymize(), "existing fields must still map")
	assert.Equal(t, int32(100), bundle.GetLogFileCount(), "existing fields must still map")
}

// newBundleJobRequest builds an api.JobRequest carrying a bundle workload with
// the given parameters, mirroring what the REST handler decodes.
func newBundleJobRequest(t *testing.T, p api.BundleParameters) *api.JobRequest {
	t.Helper()
	var wr api.WorkloadRequest
	require.NoError(t, wr.FromBundleWorkloadRequest(api.BundleWorkloadRequest{
		Type:       api.WorkloadTypeBundle,
		Parameters: p,
	}), "build bundle workload request")
	return &api.JobRequest{Workload: wr}
}

// TestNewJob_AnonymizeLevelValidation verifies the management API accepts only
// known anonymization levels (empty defaults on the client) and rejects an
// unknown value instead of silently escalating it.
func TestNewJob_AnonymizeLevelValidation(t *testing.T) {
	base := api.BundleParameters{BundleFor: false, LogFileCount: 100, Anonymize: true}

	for _, tc := range []struct {
		name    string
		level   *string
		wantErr bool
	}{
		{name: "omitted", level: nil},
		{name: "empty", level: strPtr("")},
		{name: "default", level: strPtr("default")},
		{name: "strict", level: strPtr("strict")},
		{name: "mixed case", level: strPtr("Strict")},
		{name: "padded", level: strPtr(" default ")},
		{name: "unknown", level: strPtr("verbose"), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			p.AnonymizeLevel = tc.level
			_, err := NewJob("user-1", "acc-1", "peer-1", newBundleJobRequest(t, p))
			if tc.wantErr {
				require.Error(t, err, "an unknown anonymize_level must be rejected")
				assert.Contains(t, err.Error(), "anonymize_level", "the error must name the offending field")
				return
			}
			require.NoError(t, err, "a known anonymize_level must be accepted")
		})
	}
}

// TestNewJob_AnonymizeLevelNormalized verifies an accepted level is persisted
// trimmed and lowercased, so it reaches the client as a value the client's
// lowercase-only parser resolves correctly rather than escalating to strict.
func TestNewJob_AnonymizeLevelNormalized(t *testing.T) {
	job, err := NewJob("user-1", "acc-1", "peer-1", newBundleJobRequest(t, api.BundleParameters{
		BundleFor:      false,
		LogFileCount:   100,
		Anonymize:      true,
		AnonymizeLevel: strPtr("  Default  "),
	}))
	require.NoError(t, err, "a padded known level must be accepted")

	req, err := job.ToStreamJobRequest()
	require.NoError(t, err, "ToStreamJobRequest must succeed")
	assert.Equal(t, "default", req.GetBundle().GetAnonymizeLevel(),
		"the persisted level must be normalized so the client does not resolve it to strict")
}

// TestBuildStreamBundleResponse_OmittedFieldsMapToEmpty verifies that omitted
// optional fields map to the empty proto string, which the client resolves to
// its defaults (default anonymization level, default upload server).
func TestBuildStreamBundleResponse_OmittedFieldsMapToEmpty(t *testing.T) {
	job := bundleJobFromParams(t, api.BundleParameters{
		BundleFor:     false,
		BundleForTime: 1,
		LogFileCount:  50,
		Anonymize:     false,
		// AnonymizeLevel and UploadUrl intentionally nil.
	})

	req, err := job.ToStreamJobRequest()
	require.NoError(t, err, "ToStreamJobRequest must succeed")

	bundle := req.GetBundle()
	require.NotNil(t, bundle, "the request must carry bundle parameters")
	assert.Empty(t, bundle.GetAnonymizeLevel(), "an omitted anonymize_level must map to empty so the client defaults it")
	assert.Empty(t, bundle.GetUploadUrl(), "an omitted upload_url must map to empty so the client defaults it")
}
