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
