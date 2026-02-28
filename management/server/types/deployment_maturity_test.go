package types

import "testing"

func TestEvaluateDeploymentMaturity(t *testing.T) {
	tests := []struct {
		peers    int
		policies int
		days     int
		expected DeploymentMaturity
	}{
		{1, 0, 1, DeploymentMaturityExploration},
		{3, 1, 1, DeploymentMaturityFunctional},
		{5, 2, 5, DeploymentMaturityOperational},
		{8, 3, 14, DeploymentMaturityProduction},
		{8, 3, 5, DeploymentMaturityOperational},
	}

	for _, tt := range tests {
		stage := EvaluateDeploymentMaturity(tt.peers, tt.policies, tt.days)
		if stage != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, stage)
		}
	}
}
