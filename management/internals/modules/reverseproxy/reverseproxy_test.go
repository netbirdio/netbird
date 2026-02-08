package reverseproxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validProxy() *ReverseProxy {
	return &ReverseProxy{
		Name:   "test",
		Domain: "example.com",
		Targets: []Target{
			{TargetId: "peer-1", TargetType: TargetTypePeer, Host: "10.0.0.1", Port: 80, Protocol: "http", Enabled: true},
		},
	}
}

func TestValidate_Valid(t *testing.T) {
	require.NoError(t, validProxy().Validate())
}

func TestValidate_EmptyName(t *testing.T) {
	rp := validProxy()
	rp.Name = ""
	assert.ErrorContains(t, rp.Validate(), "name is required")
}

func TestValidate_EmptyDomain(t *testing.T) {
	rp := validProxy()
	rp.Domain = ""
	assert.ErrorContains(t, rp.Validate(), "domain is required")
}

func TestValidate_NoTargets(t *testing.T) {
	rp := validProxy()
	rp.Targets = nil
	assert.ErrorContains(t, rp.Validate(), "at least one target")
}

func TestValidate_EmptyTargetId(t *testing.T) {
	rp := validProxy()
	rp.Targets[0].TargetId = ""
	assert.ErrorContains(t, rp.Validate(), "empty target_id")
}

func TestValidate_InvalidTargetType(t *testing.T) {
	rp := validProxy()
	rp.Targets[0].TargetType = "invalid"
	assert.ErrorContains(t, rp.Validate(), "invalid target_type")
}

func TestValidate_ResourceTarget(t *testing.T) {
	rp := validProxy()
	rp.Targets = append(rp.Targets, Target{
		TargetId:   "resource-1",
		TargetType: TargetTypeResource,
		Host:       "example.org",
		Port:       443,
		Protocol:   "https",
		Enabled:    true,
	})
	require.NoError(t, rp.Validate())
}

func TestValidate_MultipleTargetsOneInvalid(t *testing.T) {
	rp := validProxy()
	rp.Targets = append(rp.Targets, Target{
		TargetId:   "",
		TargetType: TargetTypePeer,
		Host:       "10.0.0.2",
		Port:       80,
		Protocol:   "http",
		Enabled:    true,
	})
	err := rp.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "target 1")
	assert.Contains(t, err.Error(), "empty target_id")
}
