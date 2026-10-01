package metrics

import (
	"net/url"
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
		return "unknown"
	}
}

// DetermineDeploymentType determines if the deployment is cloud or self-hosted
// based on the management URL string
func DetermineDeploymentType(managementURL string) DeploymentType {
	if managementURL == "" {
		return DeploymentTypeUnknown
	}

	u, err := url.Parse(managementURL)
	if err != nil {
		return DeploymentTypeSelfHosted
	}

	if strings.ToLower(u.Hostname()) == "api.netbird.io" {
		return DeploymentTypeCloud
	}

	return DeploymentTypeSelfHosted
}
