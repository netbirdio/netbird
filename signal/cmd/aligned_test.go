package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlignedHeartbeatSecretFromEnv(t *testing.T) {
	prev := alignedHeartbeatSecrets
	t.Cleanup(func() {
		alignedHeartbeatSecrets = prev
		runCmd.PersistentFlags().Lookup("aligned-heartbeat-secret").Changed = false
	})

	// During a rotation the operator lists the new and the old secret.
	t.Setenv("NB_ALIGNED_HEARTBEAT_SECRET", "new-secret,old-secret")
	setFlagsFromEnvVars(runCmd)
	require.NotNil(t, runCmd.PersistentFlags().Lookup("aligned-heartbeat-secret"), "flag must exist")
	assert.Equal(t, []string{"new-secret", "old-secret"}, alignedHeartbeatSecrets, "secrets from the env")
}
