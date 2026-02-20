package types

type DeploymentMaturity string

const (
	DeploymentMaturityExploration DeploymentMaturity = "exploration"
	DeploymentMaturityFunctional  DeploymentMaturity = "functional"
	DeploymentMaturityOperational DeploymentMaturity = "operational"
	DeploymentMaturityProduction  DeploymentMaturity = "production"
)

// EvaluateDeploymentMaturity derives an informational maturity stage
// based on local deployment characteristics (peer count, policy count,
// and account age).
//
// This signal is heuristic and intended for guidance purposes only.
// It does not affect enforcement, routing, or policy behavior.
func EvaluateDeploymentMaturity(peerCount int, policyCount int, activeDays int) DeploymentMaturity {
	if peerCount < 3 || policyCount < 1 {
		return DeploymentMaturityExploration
	}

	if peerCount >= 8 && policyCount >= 3 && activeDays >= 14 {
		return DeploymentMaturityProduction
	}

	if peerCount >= 5 && policyCount >= 2 {
		return DeploymentMaturityOperational
	}

	return DeploymentMaturityFunctional
}
