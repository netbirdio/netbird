package metrics

import (
	"strings"
)

// DeploymentType represents the type of NetBird deployment
type DeploymentType int

const (
	// DeploymentTypeUnknown represents an unknown or uninitialized deployment type
	DeploymentTypeUnknown DeploymentType = iota

	// DeploymentTypeCloud represents a cloud-hosted NetBird deployment
	DeploymentTypeCloud

	// DeploymentTypeSelfHosted represents a self-hosted NetBird deployment
	DeploymentTypeSelfHosted
)

// String returns the string representation of the deployment type
func (d DeploymentType) String() string {
	switch d {
	case DeploymentTypeCloud:
		return "cloud"
	case DeploymentTypeSelfHosted:
		return "selfhosted"
	default:
		return "selfhosted"
	}
}

// DetermineDeploymentType determines if the deployment is cloud or self-hosted
// based on the management URL string
func DetermineDeploymentType(managementURL string) DeploymentType {
	if managementURL == "" {
		return DeploymentTypeUnknown
	}

	// Check for NetBird cloud API domain
	if strings.Contains(strings.ToLower(managementURL), "api.netbird.io") {
		return DeploymentTypeCloud
	}

	return DeploymentTypeSelfHosted
}
